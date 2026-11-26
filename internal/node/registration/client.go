package registration

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/xzcode/network-ex/internal/dataplane/relay"
	"github.com/xzcode/network-ex/pkg/protocol"
)

type cached struct {
	ok    bool
	until time.Time
}
type Client struct {
	ID    string
	Key   ed25519.PrivateKey
	base  string
	http  *http.Client
	ctx   context.Context
	mu    sync.Mutex
	cache map[relay.Lease]cached
	slots chan struct{}
}

func New(ctx context.Context, id, server, ca string, key ed25519.PrivateKey) (*Client, error) {
	u, e := url.Parse(server)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || id == "" || len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("registered relay requires HTTPS management origin, node ID and private identity key")
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if ca != "" {
		pem, e := os.ReadFile(ca)
		if e != nil {
			return nil, e
		}
		pool, e := x509.SystemCertPool()
		if e != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("invalid management CA")
		}
		tlsCfg.RootCAs = pool
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = tlsCfg
	return &Client{ID: id, Key: key, base: strings.TrimRight(u.String(), "/"), http: &http.Client{Transport: tr, Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, ctx: ctx, cache: make(map[relay.Lease]cached), slots: make(chan struct{}, 32)}, nil
}
func (c *Client) request(v protocol.NodeRequest) (protocol.NodeReply, error) {
	var out protocol.NodeReply
	v.ID = c.ID
	if e := v.Sign(c.Key); e != nil {
		return out, e
	}
	b, e := json.Marshal(v)
	if e != nil {
		return out, e
	}
	r, e := http.NewRequestWithContext(c.ctx, "POST", c.base+"/api/v1/relay/node", bytes.NewReader(b))
	if e != nil {
		return out, e
	}
	r.Header.Set("Content-Type", "application/json")
	resp, e := c.http.Do(r)
	if e != nil {
		return out, e
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return out, fmt.Errorf("management node request HTTP %d", resp.StatusCode)
	}
	body, e := io.ReadAll(io.LimitReader(resp.Body, 16*1024+1))
	if e != nil {
		return out, e
	}
	if len(body) > 16*1024 {
		return out, errors.New("node response too large")
	}
	if e = json.Unmarshal(body, &out); e != nil {
		return out, e
	}
	if out.Node.ID != c.ID || out.Limits.MaxConnections < 2 || out.Limits.MaxConnections > 256 || out.Limits.BytesPerSecond < 65536 || out.Limits.BytesPerSecond > 1<<30 || (out.State != "active" && out.State != "draining") {
		return out, errors.New("invalid node response")
	}
	return out, nil
}
func (c *Client) Enroll(invite string) (protocol.NodeReply, error) {
	return c.request(protocol.NodeRequest{Action: "enroll", Identity: relay.Public(c.Key), Invite: invite})
}
func (c *Client) Heartbeat(stats protocol.NodeStats) (protocol.NodeReply, error) {
	return c.request(protocol.NodeRequest{Action: "heartbeat", Stats: &stats})
}
func (c *Client) Run(rs *relay.Server) {
	t := time.NewTicker(3 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-t.C:
			v, e := c.Heartbeat(rs.Stats())
			if e == nil {
				rs.SetLimits(v.Limits)
			} else {
				c.mu.Lock()
				clear(c.cache)
				c.mu.Unlock()
			}
		}
	}
}

// Registered relays revalidate current assignment and membership, not just
// signed lease expiration. A short bounded cache avoids duplicate checks.
func (c *Client) Authorize(l relay.Lease) bool {
	if l.Node != c.ID || l.Valid(time.Now()) != nil || c.ctx.Err() != nil {
		return false
	}
	c.mu.Lock()
	v, ok := c.cache[l]
	c.mu.Unlock()
	if ok && time.Now().Before(v.until) {
		return v.ok
	}
	select {
	case c.slots <- struct{}{}:
		defer func() { <-c.slots }()
	case <-c.ctx.Done():
		return false
	default:
		return false
	}
	b, e := json.Marshal(l)
	if e != nil {
		return false
	}
	v2, e := c.request(protocol.NodeRequest{Action: "authorize", Lease: b})
	allowed := e == nil && v2.Authorized
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.cache) >= 4096 {
		for k, v := range c.cache {
			if time.Now().After(v.until) {
				delete(c.cache, k)
			}
		}
		if len(c.cache) >= 4096 {
			clear(c.cache)
		}
	}
	c.cache[l] = cached{allowed, time.Now().Add(time.Second)}
	return allowed
}
