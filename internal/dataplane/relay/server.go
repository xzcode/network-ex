package relay

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const MaxPacket = 65507
const maxPeers = 256
const maxRate = 16 * 1024 * 1024 // per direction, bytes/sec; prototype safety limit
type Hello struct {
	Token string `json:"token"`
	ID    string `json:"id"`
	Proof string `json:"proof"`
}
type registration struct {
	lease Lease
	id    string
	ws    *websocket.Conn
	queue chan []byte
	done  chan struct{}
	once  sync.Once
}

func (r *registration) close() { r.once.Do(func() { close(r.done); r.ws.Close() }) }

type Server struct {
	Node   string
	Issuer ed25519.PublicKey
	mu     sync.Mutex
	flows  map[Lease]map[string]*registration
	slots  chan struct{}
}

func NewServer(node string, issuer ed25519.PublicKey) *Server {
	return &Server{Node: node, Issuer: issuer, flows: make(map[Lease]map[string]*registration), slots: make(chan struct{}, maxPeers)}
}

var upgrader = websocket.Upgrader{ReadBufferSize: 4096, WriteBufferSize: 4096, CheckOrigin: func(r *http.Request) bool { return r.Header.Get("Origin") == "" }}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" {
		w.Write([]byte("ok\n"))
		return
	}
	if r.URL.Path != "/relay/v1" || r.Method != "GET" {
		http.NotFound(w, r)
		return
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		http.Error(w, "capacity", 503)
		return
	}
	c, e := upgrader.Upgrade(w, r, nil)
	if e != nil {
		return
	}
	defer c.Close()
	c.SetReadLimit(MaxPacket)
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	c.SetWriteDeadline(time.Now().Add(5 * time.Second))
	ch, e := Challenge()
	if e != nil {
		return
	}
	if c.WriteJSON(map[string]string{"challenge": ch}) != nil {
		return
	}
	var h Hello
	if c.ReadJSON(&h) != nil {
		return
	}
	l, e := Verify(s.Issuer, h.Token, time.Now())
	if e != nil || l.Node != s.Node || (h.ID != l.A && h.ID != l.B) {
		return
	}
	pub, e := hex.DecodeString(h.ID)
	if e != nil {
		return
	}
	sig, e := hex.DecodeString(h.Proof)
	if e != nil || !ed25519.Verify(pub, ProofMessage(ch, h.Token, h.ID), sig) {
		return
	}
	reg := &registration{lease: l, id: h.ID, ws: c, queue: make(chan []byte, 32), done: make(chan struct{})}
	if e = s.register(reg); e != nil {
		return
	}
	defer s.remove(reg)
	defer reg.close()
	if c.WriteJSON(map[string]string{"status": "ok"}) != nil {
		return
	}
	deadline := time.Unix(l.Expires, 0)
	c.SetReadDeadline(deadline)
	timer := time.AfterFunc(time.Until(deadline), reg.close)
	defer timer.Stop()
	go func() {
		defer reg.close()
		for {
			select {
			case <-reg.done:
				return
			case b := <-reg.queue:
				c.SetWriteDeadline(time.Now().Add(5 * time.Second))
				if c.WriteMessage(websocket.BinaryMessage, b) != nil {
					return
				}
			}
		}
	}()
	window := time.Now()
	used := 0
	for {
		t, b, e := c.ReadMessage()
		if e != nil {
			return
		}
		if t != websocket.BinaryMessage || len(b) == 0 || len(b) > MaxPacket || time.Now().Unix() >= l.Expires {
			return
		}
		now := time.Now()
		if now.Sub(window) >= time.Second {
			window = now
			used = 0
		}
		used += len(b)
		if used > maxRate {
			return
		}
		s.forward(reg, b)
	}
}
func (s *Server) register(r *registration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.flows[r.lease]
	if m == nil {
		m = make(map[string]*registration)
		s.flows[r.lease] = m
	}
	if m[r.id] != nil {
		return errors.New("duplicate active identity for lease")
	}
	m[r.id] = r
	return nil
}
func (s *Server) remove(r *registration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.flows[r.lease]
	if m[r.id] == r {
		delete(m, r.id)
	}
	if len(m) == 0 {
		delete(s.flows, r.lease)
	}
}
func (s *Server) forward(r *registration, b []byte) {
	s.mu.Lock()
	m := s.flows[r.lease]
	peer := r.lease.A
	if peer == r.id {
		peer = r.lease.B
	}
	p := m[peer]
	s.mu.Unlock()
	if p == nil {
		return
	}
	select {
	case <-p.done:
	case p.queue <- b:
	default:
	}
}
