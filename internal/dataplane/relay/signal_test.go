package relay

import (
	"context"
	"crypto/ed25519"
	"encoding/pem"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestSignalScopeAndIdentity(t *testing.T) {
	pub, issuer := newKey(t)
	_, a := newKey(t)
	_, b := newKey(t)
	_, c := newKey(t)
	_, d := newKey(t)
	_, rogue := newKey(t)
	server := httptest.NewTLSServer(NewSignalServer("n", pub))
	defer server.Close()
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if e := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); e != nil {
		t.Fatal(e)
	}
	url := "wss" + strings.TrimPrefix(server.URL, "https") + "/relay/v1"
	lease := func(network string, x, y ed25519.PrivateKey) string {
		token, e := Issue(issuer, Lease{Node: "n", Network: network, Flow: "same-flow", A: Public(x), B: Public(y), Expires: time.Now().Add(time.Minute).Unix()})
		if e != nil {
			t.Fatal(e)
		}
		return token
	}
	ab, cd := lease("ab", a, b), lease("cd", c, d)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	makeClient := func(k ed25519.PrivateKey, token string) *Client {
		return &Client{URL: url, CAFile: ca, Key: k, Token: token}
	}
	offer := func(id string) Offer {
		return Offer{Ufrag: id + "1234", Password: "012345678901234567890123456789", Candidates: []string{"fixture-" + id}}
	}
	if w, _, e := makeClient(rogue, ab).Exchange(ctx, offer("rogue")); e == nil {
		w.Close()
		t.Fatal("unauthorized signal identity accepted")
	}
	type result struct {
		id     string
		ws     *websocket.Conn
		answer SignalAnswer
		err    error
	}
	results := make(chan result, 4)
	for _, v := range []struct {
		id string
		c  *Client
	}{{"a", makeClient(a, ab)}, {"b", makeClient(b, ab)}, {"c", makeClient(c, cd)}, {"d", makeClient(d, cd)}} {
		v := v
		go func() { w, ans, e := v.c.Exchange(ctx, offer(v.id)); results <- result{v.id, w, ans, e} }()
	}
	got := map[string]result{}
	for i := 0; i < 4; i++ {
		r := <-results
		if r.err != nil {
			t.Fatal(r.err)
		}
		defer r.ws.Close()
		got[r.id] = r
	}
	for x, y := range map[string]string{"a": "b", "b": "a", "c": "d", "d": "c"} {
		if got[x].answer.Offer.Ufrag != offer(y).Ufrag {
			t.Fatalf("cross-network signaling: %s", x)
		}
	}
	if got["a"].answer.Controlling == got["b"].answer.Controlling || got["c"].answer.Controlling == got["d"].answer.Controlling {
		t.Fatal("invalid role assignment")
	}
	got["a"].ws.Close()
	got["b"].ws.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, e := got["b"].ws.ReadMessage(); e == nil {
		t.Fatal("stale generation not invalidated")
	}
}
