package protocol

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

// Directory entries contain public connection metadata only.
type RelayNode struct {
	ID       string `json:"id"`
	Region   string `json:"region"`
	RelayURL string `json:"relay_url"`
	STUNURL  string `json:"stun_url,omitempty"`
}
type NodeProbe struct {
	ID        string `json:"id"`
	Reachable bool   `json:"reachable"`
	RTTMillis int    `json:"rtt_ms"`
}
type NodeStats struct {
	Connections int    `json:"connections"`
	Ingress     uint64 `json:"ingress_bytes"`
	Egress      uint64 `json:"egress_bytes"`
	Dropped     uint64 `json:"dropped_packets"`
}
type NodeLimits struct {
	MaxConnections int   `json:"max_connections"`
	BytesPerSecond int64 `json:"bytes_per_second"`
}
type NodeRequest struct {
	Action    string          `json:"action"`
	ID        string          `json:"id"`
	Identity  string          `json:"identity,omitempty"`
	Invite    string          `json:"invite,omitempty"`
	Nonce     string          `json:"nonce"`
	Timestamp int64           `json:"timestamp"`
	Stats     *NodeStats      `json:"stats,omitempty"`
	Lease     json.RawMessage `json:"lease,omitempty"`
	Signature string          `json:"signature"`
}

func (v NodeRequest) message() []byte {
	v.Signature = ""
	b, _ := json.Marshal(v)
	return append([]byte("network-ex/node/v1\x00"), b...)
}
func (v *NodeRequest) Sign(k ed25519.PrivateKey) error {
	if len(k) != ed25519.PrivateKeySize || v.ID == "" {
		return errors.New("invalid node signing identity")
	}
	n, e := random(24)
	if e != nil {
		return e
	}
	v.Nonce = n
	v.Timestamp = time.Now().Unix()
	v.Signature = hex.EncodeToString(ed25519.Sign(k, v.message()))
	return nil
}
func (v NodeRequest) Verify(identity string) bool {
	if len(v.ID) == 0 || len(v.ID) > 64 || len(v.Nonce) != 32 || v.Timestamp < now()-30 || v.Timestamp > now()+30 || !validKey(identity) {
		return false
	}
	pub, _ := hex.DecodeString(identity)
	sig, e := hex.DecodeString(v.Signature)
	return e == nil && ed25519.Verify(pub, v.message(), sig)
}

type NodeReply struct {
	Node       RelayNode  `json:"node"`
	State      string     `json:"state"`
	Limits     NodeLimits `json:"limits"`
	Authorized bool       `json:"authorized,omitempty"`
}
