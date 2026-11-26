package relay

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

const maxLifetime = 15 * time.Minute

var enc = base64.RawURLEncoding

type Lease struct {
	Node    string `json:"node"`
	Network string `json:"network"`
	Flow    string `json:"flow"`
	A       string `json:"a"`
	B       string `json:"b"`
	Expires int64  `json:"expires"`
}

func (l Lease) Valid(now time.Time) error {
	if l.Node == "" || l.Network == "" || l.Flow == "" || len(l.Node) > 128 || len(l.Network) > 128 || len(l.Flow) > 128 || l.A == l.B {
		return errors.New("invalid lease scope")
	}
	for _, v := range []string{l.A, l.B} {
		k, e := hex.DecodeString(v)
		if e != nil || len(k) != ed25519.PublicKeySize || v != strings.ToLower(v) {
			return errors.New("invalid identity")
		}
	}
	if l.Expires <= now.Unix() || l.Expires > now.Add(maxLifetime).Unix() {
		return errors.New("lease expired or exceeds lifetime")
	}
	return nil
}
func Issue(k ed25519.PrivateKey, l Lease) (string, error) {
	if len(k) != ed25519.PrivateKeySize {
		return "", errors.New("invalid issuer key")
	}
	if e := l.Valid(time.Now()); e != nil {
		return "", e
	}
	b, e := json.Marshal(l)
	if e != nil {
		return "", e
	}
	return enc.EncodeToString(b) + "." + enc.EncodeToString(ed25519.Sign(k, append([]byte("network-ex/lease/v1\x00"), b...))), nil
}
func Verify(pub ed25519.PublicKey, t string, now time.Time) (Lease, error) {
	var l Lease
	if len(pub) != ed25519.PublicKeySize || len(t) > 4096 {
		return l, errors.New("invalid token")
	}
	p := strings.Split(t, ".")
	if len(p) != 2 {
		return l, errors.New("invalid token")
	}
	b, e := enc.DecodeString(p[0])
	if e != nil {
		return l, e
	}
	s, e := enc.DecodeString(p[1])
	if e != nil {
		return l, e
	}
	if !ed25519.Verify(pub, append([]byte("network-ex/lease/v1\x00"), b...), s) {
		return l, errors.New("invalid signature")
	}
	if e = json.Unmarshal(b, &l); e != nil {
		return l, e
	}
	return l, l.Valid(now)
}
func Challenge() (string, error) {
	b := make([]byte, 32)
	_, e := rand.Read(b)
	return enc.EncodeToString(b), e
}
func ProofMessage(ch, t, id string) []byte {
	h := sha256.Sum256([]byte(t))
	return []byte(fmt.Sprintf("network-ex/relay-proof/v1\x00%s\x00%x\x00%s", ch, h, id))
}
func Public(k ed25519.PrivateKey) string { return hex.EncodeToString(k.Public().(ed25519.PublicKey)) }
func ReadHex(path string, n int, secret bool) ([]byte, error) {
	info, e := os.Stat(path)
	if e != nil {
		return nil, e
	}
	if !info.Mode().IsRegular() || info.Size() > 4096 || (secret && info.Mode().Perm()&0077 != 0) {
		return nil, errors.New("unsafe key file permissions or size")
	}
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	v, e := hex.DecodeString(strings.TrimSpace(string(b)))
	if e != nil || len(v) != n {
		return nil, errors.New("invalid hex key")
	}
	return v, nil
}
func WriteSecret(path string, b []byte) error {
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	_, e = f.WriteString(hex.EncodeToString(b) + "\n")
	return e
}
