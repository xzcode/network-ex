package relay

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func newKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	p, k, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	return p, k
}
func eventually(t *testing.T, fn func() bool) {
	t.Helper()
	for until := time.Now().Add(5 * time.Second); time.Now().Before(until); {
		if fn() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition timeout")
}
func TestSignedLeaseScope(t *testing.T) {
	pub, issuer := newKey(t)
	_, a := newKey(t)
	_, b := newKey(t)
	l := Lease{Node: "n", Network: "x", Flow: "f", A: Public(a), B: Public(b), Expires: time.Now().Add(time.Minute).Unix()}
	token, e := Issue(issuer, l)
	if e != nil {
		t.Fatal(e)
	}
	got, e := Verify(pub, token, time.Now())
	if e != nil || got != l {
		t.Fatalf("verify: %v", e)
	}
	if _, e = Verify(pub, token, time.Now().Add(2*time.Minute)); e == nil {
		t.Fatal("accepted expired lease")
	}
	parts := strings.Split(token, ".")
	parts[1] = "AAAA"
	if _, e = Verify(pub, strings.Join(parts, "."), time.Now()); e == nil {
		t.Fatal("accepted invalid signature")
	}
	l.Expires = time.Now().Add(time.Hour).Unix()
	if _, e = Issue(issuer, l); e == nil {
		t.Fatal("accepted excessive lifetime")
	}
}
func TestRelayIdentityAndFlow(t *testing.T) {
	pub, issuer := newKey(t)
	_, a := newKey(t)
	_, b := newKey(t)
	_, c := newKey(t)
	_, d := newKey(t)
	srv := httptest.NewTLSServer(NewServer("node", pub))
	defer srv.Close()
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if e := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := x509.ParseCertificate(srv.Certificate().Raw); e != nil {
		t.Fatal(e)
	}
	url := "wss" + strings.TrimPrefix(srv.URL, "https") + "/relay/v1"
	lease := func(network, flow string, k1, k2 ed25519.PrivateKey) string {
		t.Helper()
		v, e := Issue(issuer, Lease{Node: "node", Network: network, Flow: flow, A: Public(k1), B: Public(k2), Expires: time.Now().Add(time.Minute).Unix()})
		if e != nil {
			t.Fatal(e)
		}
		return v
	}
	token := lease("n1", "flow", a, b)
	other := lease("n2", "flow", c, d)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	clients := []*Client{{URL: url, CAFile: ca, Key: a, Token: token}, {URL: url, CAFile: ca, Key: b, Token: token}, {URL: url, CAFile: ca, Key: c, Token: other}, {URL: url, CAFile: ca, Key: d, Token: other}}
	recv := make([]chan []byte, len(clients))
	for i, x := range clients {
		ch := make(chan []byte, 4)
		recv[i] = ch
		go x.Run(ctx, func(b []byte) { ch <- b })
	}
	eventually(t, func() bool {
		for _, x := range clients {
			if !x.Ready() {
				return false
			}
		}
		return true
	})
	if e := clients[0].Send([]byte("test ciphertext fixture")); e != nil {
		t.Fatal(e)
	}
	select {
	case v := <-recv[1]:
		if string(v) != "test ciphertext fixture" {
			t.Fatal("payload mismatch")
		}
	case <-time.After(time.Second):
		t.Fatal("forward timeout")
	}
	select {
	case <-recv[2]:
		t.Fatal("cross-network leak")
	case <-recv[3]:
		t.Fatal("cross-network leak")
	case <-time.After(100 * time.Millisecond):
	}
	// Establish TLS but submit no valid identity proof.
	dial := websocket.Dialer{TLSClientConfig: srv.Client().Transport.(*http.Transport).TLSClientConfig}
	w, _, e := dial.Dial(url, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer w.Close()
	w.SetReadDeadline(time.Now().Add(time.Second))
	var ch map[string]string
	if e = w.ReadJSON(&ch); e != nil {
		t.Fatal(e)
	}
	if e = w.WriteJSON(Hello{Token: token, ID: Public(a), Proof: "00"}); e != nil {
		t.Fatal(e)
	}
	var ack map[string]string
	if e = w.ReadJSON(&ack); e == nil {
		t.Fatal("invalid proof accepted")
	}
}
