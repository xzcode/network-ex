//go:build !windows

package mobile

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"github.com/xzcode/network-ex/internal/control/managed"
	"os"
	"path/filepath"
	"testing"
)

func TestProfileBundleRoundTrip(t *testing.T) {
	_, id, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	wg := make([]byte, 32)
	if _, e = rand.Read(wg); e != nil {
		t.Fatal(e)
	}
	b, e := json.Marshal(profileBundle{Version: 1, State: managed.State{Server: "https://127.0.0.1", ID: "fixture", NetworkID: "fixture-net"}, Identity: id, WireGuard: wg})
	if e != nil {
		t.Fatal(e)
	}
	a, c := t.TempDir(), t.TempDir()
	os.Chmod(a, 0700)
	os.Chmod(c, 0700)
	if e = ImportProfile(a, b); e != nil {
		t.Fatal(e)
	}
	out, e := ExportProfile(a)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(b, out) {
		t.Fatal("credentials changed on export")
	}
	if e = ImportProfile(c, out); e != nil {
		t.Fatal(e)
	}
	if e = ImportProfile(c, out); e == nil {
		t.Fatal("existing profile overwritten")
	}
	if e = Forget(a); e != nil {
		t.Fatal(e)
	}
	if !HasProfile(c) || HasProfile(a) {
		t.Fatal("profile deletion isolation")
	}
	bad := t.TempDir()
	os.Chmod(bad, 0700)
	if e = ImportProfile(bad, append(out, []byte(" {}")...)); e == nil {
		t.Fatal("trailing JSON accepted")
	}
	var x profileBundle
	json.Unmarshal(out, &x)
	x.State.CA = "/etc/passwd"
	raw, _ := json.Marshal(x)
	if e = ImportProfile(bad, raw); e == nil {
		t.Fatal("absolute CA path accepted")
	}
	if _, e = os.Stat(filepath.Join(bad, "device")); !os.IsNotExist(e) {
		t.Fatal("invalid bundle left device")
	}
}
