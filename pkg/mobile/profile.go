package mobile

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"github.com/xzcode/network-ex/internal/control/managed"
	"github.com/xzcode/network-ex/internal/dataplane/relay"
	"github.com/xzcode/network-ex/internal/platform/localfile"
	"io"
	"os"
	"path/filepath"
)

// Opaque credential bundle for native Keychain integration only. Never log it
// or put it in a VPN configuration or shared plaintext file.
type profileBundle struct {
	Version   int           `json:"version"`
	State     managed.State `json:"state"`
	Identity  []byte        `json:"identity"`
	WireGuard []byte        `json:"wireguard"`
	CA        []byte        `json:"ca,omitempty"`
}

func ExportProfile(root string) ([]byte, error) {
	root, e := checkedRoot(root)
	if e != nil {
		return nil, e
	}
	unlock, e := lockRoot(root)
	if e != nil {
		return nil, e
	}
	defer unlock()
	dir := filepath.Join(root, "device")
	st, e := managed.Load(dir)
	if e != nil {
		return nil, e
	}
	id, e := relay.ReadHex(filepath.Join(dir, "identity.key"), ed25519.PrivateKeySize, true)
	if e != nil {
		return nil, e
	}
	wg, e := relay.ReadHex(filepath.Join(dir, "wg.key"), 32, true)
	if e != nil {
		return nil, e
	}
	v := profileBundle{Version: 1, State: st, Identity: id, WireGuard: wg}
	if st.CA != "" {
		if st.CA != filepath.Join(root, "private-ca.pem") {
			return nil, errors.New("unexpected profile CA location")
		}
		if e = localfile.Check(st.CA, false, 32768); e != nil {
			return nil, e
		}
		v.CA, e = os.ReadFile(st.CA)
		if e != nil {
			return nil, e
		}
	}
	v.State.CA = ""
	return json.Marshal(v)
}
func ImportProfile(root string, raw []byte) error {
	if len(raw) == 0 || len(raw) > 65536 {
		return errors.New("invalid profile bundle size")
	}
	var v profileBundle
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if e := dec.Decode(&v); e != nil {
		return e
	}
	var extra any
	if e := dec.Decode(&extra); e != io.EOF {
		return errors.New("unexpected trailing profile content")
	}
	if v.Version != 1 || v.State.CA != "" || v.State.ID == "" || v.State.NetworkID == "" || len(v.Identity) != 64 || len(v.WireGuard) != 32 || len(v.CA) > 32768 {
		return errors.New("invalid profile bundle")
	}
	if !bytes.Equal(ed25519.NewKeyFromSeed(v.Identity[:32]), v.Identity) || bytes.Equal(v.WireGuard, make([]byte, 32)) {
		return errors.New("invalid identity keys")
	}
	root, e := checkedRoot(root)
	if e != nil {
		return e
	}
	unlock, e := lockRoot(root)
	if e != nil {
		return e
	}
	defer unlock()
	dir := filepath.Join(root, "device")
	if e = os.Mkdir(dir, 0700); e != nil {
		return e
	}
	ca := filepath.Join(root, "private-ca.pem")
	madeCA := false
	ok := false
	defer func() {
		if !ok {
			os.RemoveAll(dir)
			if madeCA {
				os.Remove(ca)
			}
		}
	}()
	if len(v.CA) > 0 {
		f, e := os.OpenFile(ca, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return e
		}
		madeCA = true
		_, e = f.Write(v.CA)
		ce := f.Close()
		if e != nil {
			return e
		}
		if ce != nil {
			return ce
		}
		v.State.CA = ca
	}
	if _, e = managed.NewClient(v.State.Server, v.State.CA); e != nil {
		return e
	}
	if e = relay.WriteSecret(filepath.Join(dir, "identity.key"), v.Identity); e != nil {
		return e
	}
	if e = relay.WriteSecret(filepath.Join(dir, "wg.key"), v.WireGuard); e != nil {
		return e
	}
	b, e := json.Marshal(v.State)
	if e != nil {
		return e
	}
	if e = os.WriteFile(filepath.Join(dir, "state.json"), b, 0600); e != nil {
		return e
	}
	if _, e = managed.Load(dir); e != nil {
		return e
	}
	ok = true
	return nil
}
