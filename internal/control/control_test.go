package control

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/xzcode/network-ex/internal/dataplane/relay"
	"golang.org/x/crypto/curve25519"
)

func TestManagedAuthorizationLifecycle(t *testing.T) {
	store, e := Open(filepath.Join(t.TempDir(), "network.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	if e = store.Bootstrap("admin", "strong-test-password"); e != nil {
		t.Fatal(e)
	}
	pub, priv, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	s, e := NewService(store, priv, "test-node", "wss://127.0.0.1:8443/relay/v1", "")
	if e != nil {
		t.Fatal(e)
	}
	h := s.Handler()
	call := func(method, path, token string, in, out any, expect int) {
		t.Helper()
		var b []byte
		if in != nil {
			b, _ = json.Marshal(in)
		}
		r := httptest.NewRequest(method, path, bytes.NewReader(b))
		if in != nil {
			r.Header.Set("Content-Type", "application/json")
		}
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != expect {
			t.Fatalf("%s %s: status %d want %d: %s", method, path, w.Code, expect, w.Body.String())
		}
		if out != nil {
			if e := json.Unmarshal(w.Body.Bytes(), out); e != nil {
				t.Fatal(e)
			}
		}
	}
	var login struct{ Token string }
	call(http.MethodPost, "/api/v1/auth/login", "", map[string]string{"login": "admin", "password": "strong-test-password"}, &login, 200)
	var n Network
	call(http.MethodPost, "/api/v1/networks", login.Token, map[string]string{"name": "test", "cidr": "10.88.0.0/24", "policy": "deny_members"}, &n, 201)
	type localDevice struct {
		d Device
		k ed25519.PrivateKey
	}
	enroll := func(name string) localDevice {
		t.Helper()
		var invite struct{ Invite string }
		call(http.MethodPost, "/api/v1/networks/"+n.ID+"/invites", login.Token, map[string]int{"ttl_seconds": 3600}, &invite, 201)
		p, k, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		scalar := make([]byte, 32)
		if _, e = rand.Read(scalar); e != nil {
			t.Fatal(e)
		}
		wg, e := curve25519.X25519(scalar, curve25519.Basepoint)
		if e != nil {
			t.Fatal(e)
		}
		req := Enrollment{Invite: invite.Invite, Name: name, Identity: hex.EncodeToString(p), WGKey: hex.EncodeToString(wg)}
		req.Sign(k)
		var d Device
		call(http.MethodPost, "/api/v1/devices/enroll", "", req, &d, 201)
		call(http.MethodPost, "/api/v1/devices/enroll", "", req, nil, 403)
		return localDevice{d, k}
	}
	a, b := enroll("a"), enroll("b")
	snapshot := func(x localDevice) Snapshot {
		t.Helper()
		r := DeviceRequest{ID: x.d.ID}
		if e := r.Sign(x.k); e != nil {
			t.Fatal(e)
		}
		var snap Snapshot
		call(http.MethodPost, "/api/v1/devices/snapshot", "", r, &snap, 200)
		call(http.MethodPost, "/api/v1/devices/snapshot", "", r, nil, 409)
		return snap
	}
	if x := snapshot(a); x.Device.Status != "pending" || len(x.Peers) != 0 {
		t.Fatalf("pending snapshot leaked peers")
	}
	for _, x := range []localDevice{a, b} {
		call(http.MethodPost, "/api/v1/networks/"+n.ID+"/devices/"+x.d.ID+"/approve", login.Token, map[string]any{}, nil, 200)
	}
	if x := snapshot(a); len(x.Peers) != 0 {
		t.Fatal("default deny ignored")
	}
	rule := Rule{A: a.d.ID, B: b.d.ID, Allow: true}
	call(http.MethodPut, "/api/v1/networks/"+n.ID+"/rules", login.Token, rule, nil, 200)
	sa, sb := snapshot(a), snapshot(b)
	if len(sa.Peers) != 1 || len(sb.Peers) != 1 {
		t.Fatal("allow rule missing peer")
	}
	if sa.Device.IP == sb.Device.IP {
		t.Fatal("duplicate IP")
	}
	la, e := relay.Verify(pub, sa.Peers[0].Lease, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	lb, e := relay.Verify(pub, sb.Peers[0].Lease, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	if la.Expires == lb.Expires && sa.Peers[0].Lease != sb.Peers[0].Lease {
		t.Fatal("pair did not receive same lease")
	}
	if !s.AuthorizeLease(la) || !s.AuthorizeLease(lb) {
		t.Fatal("valid leases rejected")
	}
	wrong := DeviceRequest{ID: a.d.ID}
	if e := wrong.Sign(b.k); e != nil {
		t.Fatal(e)
	}
	call(http.MethodPost, "/api/v1/devices/snapshot", "", wrong, nil, 401)
	rule.Allow = false
	call(http.MethodPut, "/api/v1/networks/"+n.ID+"/rules", login.Token, rule, nil, 200)
	if s.AuthorizeLease(la) || len(snapshot(a).Peers) != 0 || len(snapshot(b).Peers) != 0 {
		t.Fatal("old authorization survived rule change")
	}
	rule.Allow = true
	call(http.MethodPut, "/api/v1/networks/"+n.ID+"/rules", login.Token, rule, nil, 200)
	sa = snapshot(a)
	if len(sa.Peers) != 1 {
		t.Fatal("rule not restored")
	}
	la, e = relay.Verify(pub, sa.Peers[0].Lease, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	call(http.MethodPost, "/api/v1/networks/"+n.ID+"/devices/"+b.d.ID+"/revoke", login.Token, map[string]any{}, nil, 200)
	if s.AuthorizeLease(la) || len(snapshot(a).Peers) != 0 {
		t.Fatal("revocation not enforced")
	}
	if x := snapshot(b); x.Device.Status != "revoked" || len(x.Peers) != 0 {
		t.Fatal("revoked snapshot leaked peers")
	}
}
