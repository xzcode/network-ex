package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"
)

type Enrollment struct {
	Invite    string `json:"invite"`
	Name      string `json:"name"`
	Identity  string `json:"identity"`
	WGKey     string `json:"wg_key"`
	Signature string `json:"signature"`
}

func (v Enrollment) message() []byte {
	v.Signature = ""
	b, _ := json.Marshal(v)
	return append([]byte("network-ex/enroll/v1\x00"), b...)
}
func (v *Enrollment) Sign(key ed25519.PrivateKey) {
	v.Signature = hex.EncodeToString(ed25519.Sign(key, v.message()))
}
func validKey(s string) bool {
	v, e := hex.DecodeString(s)
	return e == nil && len(v) == 32 && s == strings.ToLower(s) && strings.Trim(s, "0") != ""
}
func (v Enrollment) Verify() bool {
	if len(v.Invite) != 43 || len(v.Name) < 1 || len(v.Name) > 80 || !validKey(v.Identity) || !validKey(v.WGKey) {
		return false
	}
	wg, _ := hex.DecodeString(v.WGKey)
	if _, e := curve25519.X25519(make([]byte, 32), wg); e != nil {
		return false
	}
	pub, _ := hex.DecodeString(v.Identity)
	sig, e := hex.DecodeString(v.Signature)
	return e == nil && ed25519.Verify(pub, v.message(), sig)
}

type DeviceRequest struct {
	ID        string `json:"id"`
	Nonce     string `json:"nonce"`
	Timestamp int64  `json:"timestamp"`
	Signature string `json:"signature"`
}

func (v DeviceRequest) message() []byte {
	v.Signature = ""
	b, _ := json.Marshal(v)
	return append([]byte("network-ex/snapshot/v1\x00"), b...)
}
func (v *DeviceRequest) Sign(key ed25519.PrivateKey) error {
	if v.ID == "" {
		return errors.New("device ID required")
	}
	n, e := random(24)
	if e != nil {
		return e
	}
	v.Nonce = n
	v.Timestamp = time.Now().Unix()
	v.Signature = hex.EncodeToString(ed25519.Sign(key, v.message()))
	return nil
}
func (v DeviceRequest) Verify(identity string) bool {
	if len(v.ID) > 64 || len(v.Nonce) != 32 || v.Timestamp < now()-30 || v.Timestamp > now()+30 || !validKey(identity) {
		return false
	}
	pub, _ := hex.DecodeString(identity)
	sig, e := hex.DecodeString(v.Signature)
	return e == nil && ed25519.Verify(pub, v.message(), sig)
}

type Device struct {
	ID        string `json:"id"`
	NetworkID string `json:"network_id"`
	Name      string `json:"name"`
	IP        string `json:"ip"`
	Status    string `json:"status"`
	LastSeen  int64  `json:"last_seen"`
}
type Network struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	CIDR     string `json:"cidr"`
	Revision int64  `json:"revision"`
	Policy   string `json:"policy"`
	OwnerID  string `json:"owner_id"`
}
type Rule struct {
	A     string `json:"a"`
	B     string `json:"b"`
	Allow bool   `json:"allow"`
}
type Peer struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	IP    string `json:"ip"`
	WGKey string `json:"wg_key"`
	Lease string `json:"lease"`
}
type Snapshot struct {
	Device     Device `json:"device"`
	Revision   int64  `json:"revision"`
	ValidUntil int64  `json:"valid_until"`
	RelayURL   string `json:"relay_url"`
	STUNURL    string `json:"stun_url"`
	Peers      []Peer `json:"peers"`
}

func now() int64 { return time.Now().Unix() }
func random(n int) (string, error) {
	b := make([]byte, n)
	_, e := rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b), e
}
