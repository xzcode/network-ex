package discovery

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/xzcode/network-ex/pkg/protocol"
)

func ip(s string) netip.Addr { return netip.MustParseAddr(s) }
func packet(src, dst string, port uint16, payload int) []byte {
	b := make([]byte, 28+payload)
	b[0] = 0x45
	b[8] = 64
	b[9] = 17
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	copy(b[12:16], ip(src).AsSlice())
	copy(b[16:20], ip(dst).AsSlice())
	binary.BigEndian.PutUint16(b[20:22], 40000)
	binary.BigEndian.PutUint16(b[22:24], port)
	binary.BigEndian.PutUint16(b[24:26], uint16(len(b)-20))
	binary.BigEndian.PutUint16(b[10:12], checksum(b[:20]))
	return b
}
func TestCodecAuthenticatedFanoutAndPolicy(t *testing.T) {
	a, b, c := ip("10.88.0.1"), ip("10.88.0.2"), ip("10.88.0.3")
	rules := []protocol.DiscoveryRule{{Destination: "10.88.0.255", Port: 27015}}
	onlyTCP := &protocol.TrafficPolicy{Services: []protocol.ServicePort{{Protocol: "tcp", Port: 27015}}}
	tx := New(a, rules, []Peer{{IP: b}, {IP: c, Traffic: onlyTCP}})
	rx := New(b, rules, []Peer{{IP: a}})
	p := packet(a.String(), "10.88.0.255", 27015, 32)
	frames := tx.Encode(p)
	if len(frames) != 1 || addr(frames[0][16:20]) != b {
		t.Fatal("unexpected fanout")
	}
	out := rx.Decode(frames[0])
	if out == nil || addr(out[12:16]) != a || addr(out[16:20]) != ip("10.88.0.255") || out[8] != 1 || checksum(out[:20]) != 0 || binary.BigEndian.Uint16(out[20:22]) != 40000 {
		t.Fatal("discovery packet was not preserved")
	}
	if New(b, rules, nil).Decode(frames[0]) != nil {
		t.Fatal("non-member accepted")
	}
	if New(b, rules, []Peer{{IP: a, Traffic: onlyTCP}}).Decode(frames[0]) != nil {
		t.Fatal("receiver ACL bypass")
	}
	forged := append([]byte(nil), frames[0]...)
	copy(forged[32:36], c.AsSlice())
	if rx.Decode(forged) != nil {
		t.Fatal("forged inner source accepted")
	}
	forged = append([]byte(nil), frames[0]...)
	binary.BigEndian.PutUint16(forged[42:44], 27016)
	if rx.Decode(forged) != nil {
		t.Fatal("forged destination port accepted")
	}
	if tx.Encode(packet(c.String(), "10.88.0.255", 27015, 1)) != nil {
		t.Fatal("forged local source accepted")
	}
	if tx.Encode(packet(a.String(), "10.88.0.255", 27016, 1)) != nil {
		t.Fatal("unapproved port accepted")
	}
	if tx.Encode(packet(a.String(), "10.88.0.255", 27015, 1200)) != nil {
		t.Fatal("oversize datagram accepted")
	}
	frag := packet(a.String(), "10.88.0.255", 27015, 1)
	frag[6] = 0x20
	if tx.Encode(frag) != nil {
		t.Fatal("fragment accepted")
	}
	if tx.Encode(frames[0]) != nil {
		t.Fatal("nested discovery frame accepted")
	}
}
func TestRateAndFanoutBounds(t *testing.T) {
	var bucket rate
	now := time.Unix(100, 0)
	for i := 0; i < 16; i++ {
		if !bucket.take(now, 16, 16) {
			t.Fatal("burst rejected")
		}
	}
	if bucket.take(now, 16, 16) {
		t.Fatal("burst exceeded")
	}
	if !bucket.take(now.Add(time.Second), 16, 16) {
		t.Fatal("token not refilled")
	}
	peers := []Peer{}
	for i := 2; i <= 65; i++ {
		peers = append(peers, Peer{IP: netip.AddrFrom4([4]byte{10, 88, 0, byte(i)})})
	}
	c := New(ip("10.88.0.1"), []protocol.DiscoveryRule{{Destination: "239.88.0.7", Port: 27015}}, peers)
	p := packet("10.88.0.1", "239.88.0.7", 27015, 16)
	n := 0
	for i := 0; i < 3; i++ {
		n += len(c.Encode(p))
	}
	if n != 128 {
		t.Fatalf("fanout burst = %d, want 128", n)
	}
}
