package relay

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// Offer is a single ICE generation; its credentials are exchanged only with
// the other authenticated member of the same signed lease.
type Offer struct {
	Ufrag      string   `json:"ufrag"`
	Password   string   `json:"password"`
	Candidates []string `json:"candidates"`
}

func (o Offer) Valid() bool {
	if len(o.Ufrag) < 4 || len(o.Ufrag) > 256 || len(o.Password) < 22 || len(o.Password) > 256 || len(o.Candidates) > 16 {
		return false
	}
	for _, c := range o.Candidates {
		if len(c) == 0 || len(c) > 512 {
			return false
		}
	}
	return true
}

type SignalAnswer struct {
	Offer       Offer `json:"offer"`
	Controlling bool  `json:"controlling"`
	Expires     int64 `json:"expires"`
}
type signalPeer struct {
	id     string
	ws     *websocket.Conn
	offer  Offer
	answer chan SignalAnswer
	done   chan struct{}
	once   sync.Once
}

func (p *signalPeer) close() { p.once.Do(func() { close(p.done); p.ws.Close() }) }

type SignalServer struct {
	Authorize func(Lease) bool
	node      string
	issuer    ed25519.PublicKey
	mu        sync.Mutex
	flows     map[Lease]map[string]*signalPeer
	slots     chan struct{}
}

func NewSignalServer(node string, issuer ed25519.PublicKey) *SignalServer {
	return &SignalServer{node: node, issuer: issuer, flows: make(map[Lease]map[string]*signalPeer), slots: make(chan struct{}, 256)}
}
func (s *SignalServer) join(l Lease, p *signalPeer) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.flows[l]
	if m == nil {
		m = make(map[string]*signalPeer)
		s.flows[l] = m
	}
	if m[p.id] != nil {
		return false
	}
	m[p.id] = p
	other := l.A
	if other == p.id {
		other = l.B
	}
	if q := m[other]; q != nil {
		p.answer <- SignalAnswer{Offer: q.offer, Controlling: p.id < q.id, Expires: l.Expires}
		q.answer <- SignalAnswer{Offer: p.offer, Controlling: q.id < p.id, Expires: l.Expires}
	}
	return true
}
func (s *SignalServer) leave(l Lease, p *signalPeer) {
	s.mu.Lock()
	m := s.flows[l]
	if m[p.id] != p {
		s.mu.Unlock()
		return
	}
	// Tear down the paired generation atomically before closing sockets.
	delete(s.flows, l)
	s.mu.Unlock()
	for _, q := range m {
		q.close()
	}
}
func (s *SignalServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/signal/v1" || r.Method != "GET" {
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
	c.SetReadLimit(16 * 1024)
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
	l, e := Verify(s.issuer, h.Token, time.Now())
	if e != nil || l.Node != s.node || (h.ID != l.A && h.ID != l.B) {
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
	if s.Authorize != nil && !s.Authorize(l) {
		return
	}
	if c.WriteJSON(map[string]string{"status": "ok"}) != nil {
		return
	}
	var offer Offer
	if c.ReadJSON(&offer) != nil || !offer.Valid() {
		return
	}
	p := &signalPeer{id: h.ID, ws: c, offer: offer, answer: make(chan SignalAnswer, 1), done: make(chan struct{})}
	if !s.join(l, p) {
		return
	}
	defer s.leave(l, p)
	defer p.close()
	deadline := time.Unix(l.Expires, 0)
	c.SetReadDeadline(deadline)
	timer := time.AfterFunc(time.Until(deadline), p.close)
	defer timer.Stop()
	if s.Authorize != nil {
		go func() {
			tick := time.NewTicker(time.Second)
			defer tick.Stop()
			for {
				select {
				case <-p.done:
					return
				case <-tick.C:
					if !s.Authorize(l) {
						p.close()
						return
					}
				}
			}
		}()
	}

	// Further application messages are forbidden for this generation.
	go func() { defer p.close(); c.ReadMessage() }()
	select {
	case <-p.done:
		return
	case <-time.After(20 * time.Second):
		return
	case a := <-p.answer:
		c.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if c.WriteJSON(a) != nil {
			return
		}
	}
	<-p.done
}

// Exchange opens a dedicated TLS signaling channel; keep it open for the
// lifetime of this generation. Closure invalidates both peers' generation.
func (c *Client) Exchange(ctx context.Context, offer Offer) (*websocket.Conn, SignalAnswer, error) {
	var out SignalAnswer
	u, e := url.Parse(c.URL)
	if e != nil || u.Scheme != "wss" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, out, errors.New("signal requires wss URL")
	}
	u.Path = "/signal/v1"
	u.RawPath = ""
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if c.CAFile != "" {
		pem, e := os.ReadFile(c.CAFile)
		if e != nil {
			return nil, out, e
		}
		pool, e := x509.SystemCertPool()
		if e != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, out, errors.New("invalid CA")
		}
		cfg.RootCAs = pool
	}
	d := websocket.Dialer{TLSClientConfig: cfg, HandshakeTimeout: 5 * time.Second}
	if c.Protect != nil {
		d.NetDialContext = c.Protect.Dial
	}
	ws, resp, e := d.DialContext(ctx, u.String(), nil)
	if e != nil {
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
		return nil, out, e
	}
	ok := false
	defer func() {
		if !ok {
			ws.Close()
		}
	}()
	stop := context.AfterFunc(ctx, func() { ws.Close() })
	defer stop()
	ws.SetReadLimit(16 * 1024)
	ws.SetReadDeadline(time.Now().Add(5 * time.Second))
	ws.SetWriteDeadline(time.Now().Add(5 * time.Second))
	var ch map[string]string
	if e = ws.ReadJSON(&ch); e != nil || len(ch["challenge"]) != 43 {
		return nil, out, errors.New("invalid signal challenge")
	}
	id := Public(c.Key)
	proof := ed25519.Sign(c.Key, ProofMessage(ch["challenge"], c.Token, id))
	if e = ws.WriteJSON(Hello{Token: c.Token, ID: id, Proof: hex.EncodeToString(proof)}); e != nil {
		return nil, out, e
	}
	var ack map[string]string
	if e = ws.ReadJSON(&ack); e != nil || ack["status"] != "ok" {
		return nil, out, errors.New("signal authentication failed")
	}
	if e = ws.WriteJSON(offer); e != nil {
		return nil, out, e
	}
	ws.SetReadDeadline(time.Now().Add(22 * time.Second))
	if e = ws.ReadJSON(&out); e != nil || !out.Offer.Valid() || out.Expires <= time.Now().Unix() || out.Expires > time.Now().Add(15*time.Minute).Unix() {
		return nil, out, errors.New("invalid signal answer")
	}
	ws.SetReadDeadline(time.Unix(out.Expires, 0))
	ok = true
	return ws, out, nil
}
