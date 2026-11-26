package relay

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/gorilla/websocket"
	"github.com/xzcode/network-ex/internal/platform/protect"
	"net/url"
	"os"
	"sync"
	"time"
)

type Client struct {
	Protect            protect.Protector
	URL, Token, CAFile string
	Key                ed25519.PrivateKey
	mu                 sync.RWMutex
	c                  *websocket.Conn
	send               chan []byte
}

func (c *Client) Run(ctx context.Context, deliver func([]byte)) {
	c.mu.Lock()
	c.send = make(chan []byte, 32)
	c.mu.Unlock()
	delay := time.Second
	for ctx.Err() == nil {
		start := time.Now()
		_ = c.session(ctx, deliver)
		if time.Since(start) > 30*time.Second {
			delay = time.Second
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		if delay < 30*time.Second {
			delay *= 2
			if delay > 30*time.Second {
				delay = 30 * time.Second
			}
		}
	}
}
func (c *Client) Ready() bool { c.mu.RLock(); defer c.mu.RUnlock(); return c.c != nil }
func (c *Client) Send(p []byte) error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.c == nil {
		return errors.New("relay not connected")
	}
	b := append([]byte(nil), p...)
	select {
	case c.send <- b:
		return nil
	default:
		return errors.New("relay queue full")
	}
}
func (c *Client) session(ctx context.Context, deliver func([]byte)) error {
	u, e := url.Parse(c.URL)
	if e != nil || u.Scheme != "wss" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("relay requires wss URL")
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if c.CAFile != "" {
		pem, e := os.ReadFile(c.CAFile)
		if e != nil {
			return e
		}
		pool, e := x509.SystemCertPool()
		if e != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return errors.New("invalid CA")
		}
		cfg.RootCAs = pool
	}
	d := websocket.Dialer{TLSClientConfig: cfg, HandshakeTimeout: 5 * time.Second}
	if c.Protect != nil {
		d.NetDialContext = c.Protect.Dial
	}
	ws, resp, e := d.DialContext(ctx, c.URL, nil)
	if e != nil {
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
		return e
	}
	defer ws.Close()
	stop := context.AfterFunc(ctx, func() { ws.Close() })
	defer stop()
	ws.SetReadLimit(MaxPacket)
	ws.SetReadDeadline(time.Now().Add(5 * time.Second))
	ws.SetWriteDeadline(time.Now().Add(5 * time.Second))
	var challenge map[string]string
	if e = ws.ReadJSON(&challenge); e != nil {
		return e
	}
	ch := challenge["challenge"]
	if len(ch) != 43 {
		return errors.New("invalid challenge")
	}
	id := Public(c.Key)
	proof := ed25519.Sign(c.Key, ProofMessage(ch, c.Token, id))
	if e = ws.WriteJSON(Hello{Token: c.Token, ID: id, Proof: hex.EncodeToString(proof)}); e != nil {
		return e
	}
	var ack map[string]string
	if e = ws.ReadJSON(&ack); e != nil || ack["status"] != "ok" {
		return fmt.Errorf("relay auth rejected")
	}
	ws.SetReadDeadline(time.Time{})
	ws.SetWriteDeadline(time.Time{})
	c.mu.Lock()
	for len(c.send) > 0 {
		<-c.send
	}
	c.c = ws
	c.mu.Unlock()
	defer func() { c.mu.Lock(); c.c = nil; c.mu.Unlock() }()
	done := make(chan struct{})
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		defer ws.Close()
		for {
			select {
			case <-ctx.Done():
				return
			case <-done:
				return
			case b := <-c.send:
				ws.SetWriteDeadline(time.Now().Add(5 * time.Second))
				if ws.WriteMessage(websocket.BinaryMessage, b) != nil {
					return
				}
			}
		}
	}()
	defer func() { close(done); ws.Close(); <-writerDone }()
	for {
		t, b, e := ws.ReadMessage()
		if e != nil {
			return e
		}
		if t != websocket.BinaryMessage || len(b) == 0 || len(b) > MaxPacket {
			return errors.New("invalid relay frame")
		}
		deliver(b)
	}
}
