package ethernet

import (
	"bytes"
	"encoding/binary"
	"github.com/xzcode/network-ex/internal/dataplane/guard"
	"github.com/xzcode/network-ex/pkg/protocol"
	"net/netip"
	"testing"
	"time"
)

func testIP(s string) netip.Addr { return netip.MustParseAddr(s) }
func testCodec(t *testing.T, local netip.Addr, peers []Peer, rules []protocol.DiscoveryRule) *Codec {
	t.Helper()
	gp := []guard.Peer{}
	for _, p := range peers {
		gp = append(gp, guard.Peer{Prefixes: []netip.Prefix{netip.PrefixFrom(p.IP, 32)}, Policy: p.Traffic})
	}
	g, e := guard.New([]netip.Prefix{netip.PrefixFrom(local, 32)}, gp)
	if e != nil {
		t.Fatal(e)
	}
	c, e := New(local, netip.MustParsePrefix("10.88.0.0/24"), rules, peers, g)
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func arpRequest(a, b netip.Addr) []byte {
	f := make([]byte, 42)
	copy(f[:6], broadcastMAC)
	copy(f[6:12], protocol.VirtualMAC(a))
	binary.BigEndian.PutUint16(f[12:14], arpType)
	p := f[14:]
	binary.BigEndian.PutUint16(p, 1)
	binary.BigEndian.PutUint16(p[2:], ipType)
	p[4] = 6
	p[5] = 4
	binary.BigEndian.PutUint16(p[6:], 1)
	copy(p[8:14], protocol.VirtualMAC(a))
	copy(p[14:18], a.AsSlice())
	copy(p[24:28], b.AsSlice())
	return f
}
func udpFrame(a, b netip.Addr, port uint16) []byte {
	f := make([]byte, 14+28+4)
	if b.IsMulticast() {
		copy(f[:6], multicastMAC(b))
	} else if b == testIP("10.88.0.255") {
		copy(f[:6], broadcastMAC)
	} else {
		copy(f[:6], protocol.VirtualMAC(b))
	}
	copy(f[6:12], protocol.VirtualMAC(a))
	binary.BigEndian.PutUint16(f[12:14], ipType)
	p := f[14:]
	p[0] = 0x45
	p[8] = 64
	p[9] = 17
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	copy(p[12:16], a.AsSlice())
	copy(p[16:20], b.AsSlice())
	binary.BigEndian.PutUint16(p[20:22], 40000)
	binary.BigEndian.PutUint16(p[22:24], port)
	binary.BigEndian.PutUint16(p[24:26], uint16(len(p)-20))
	binary.BigEndian.PutUint16(p[10:12], checksum(p[:20]))
	return f
}
func TestEthernetOwnershipAndARP(t *testing.T) {
	a, b, c := testIP("10.88.0.1"), testIP("10.88.0.2"), testIP("10.88.0.3")
	tx := testCodec(t, a, []Peer{{IP: b}, {IP: c}}, nil)
	rx := testCodec(t, b, []Peer{{IP: a}}, nil)
	req := arpRequest(a, b)
	frames := tx.Encode(req)
	if len(frames) != 1 || ip(frames[0][16:20]) != b || !bytes.Equal(rx.Decode(frames[0]), req) {
		t.Fatal("ARP must target only the allocated peer and preserve frame")
	}
	spoof := append([]byte(nil), req...)
	copy(spoof[28:32], c.AsSlice())
	if tx.Encode(spoof) != nil || rx.Decode(envelope(a, b, spoof)) != nil {
		t.Fatal("ARP spoof accepted")
	}
	if tx.Encode(arpRequest(a, testIP("10.88.0.99"))) != nil {
		t.Fatal("unknown target ARP flooded")
	}
	if testCodec(t, b, nil, nil).Decode(frames[0]) != nil {
		t.Fatal("nonmember frame accepted")
	}
	f := udpFrame(a, b, 27015)
	frames = tx.Encode(f)
	if len(frames) != 1 || !bytes.Equal(rx.Decode(frames[0]), f) {
		t.Fatal("unicast frame not preserved")
	}
	forged := append([]byte(nil), f...)
	copy(forged[6:12], protocol.VirtualMAC(c))
	if tx.Encode(forged) != nil || rx.Decode(envelope(a, b, forged)) != nil {
		t.Fatal("forged Ethernet source accepted")
	}
	forged = append([]byte(nil), f...)
	copy(forged[26:30], c.AsSlice())
	if rx.Decode(envelope(a, b, forged)) != nil {
		t.Fatal("forged inner IP accepted")
	}
	forged = append([]byte(nil), f...)
	copy(forged[:6], protocol.VirtualMAC(c))
	if tx.Encode(forged) != nil || rx.Decode(envelope(a, b, forged)) != nil {
		t.Fatal("unknown destination MAC accepted")
	}
	forged = append([]byte(nil), f...)
	binary.BigEndian.PutUint16(forged[12:14], 0x8100)
	if tx.Encode(forged) != nil || rx.Decode(envelope(a, b, forged)) != nil {
		t.Fatal("VLAN frame accepted")
	}
}
func TestEthernetDiscoveryACLAndLimits(t *testing.T) {
	a, b, c := testIP("10.88.0.1"), testIP("10.88.0.2"), testIP("10.88.0.3")
	dst := testIP("239.88.0.7")
	rules := []protocol.DiscoveryRule{{Destination: dst.String(), Port: 27015}}
	allow := &protocol.TrafficPolicy{Services: []protocol.ServicePort{{Protocol: "udp", Port: 27015}}}
	deny := &protocol.TrafficPolicy{Services: []protocol.ServicePort{{Protocol: "tcp", Port: 27015}}}
	tx := testCodec(t, a, []Peer{{IP: b, Discovery: true, Traffic: allow}, {IP: c, Discovery: true, Traffic: deny}}, rules)
	rx := testCodec(t, b, []Peer{{IP: a, Discovery: true, Traffic: allow}}, rules)
	f := udpFrame(a, dst, 27015)
	out := tx.Encode(f)
	if len(out) != 1 || ip(out[0][16:20]) != b {
		t.Fatal("group ACL fanout")
	}
	got := rx.Decode(out[0])
	if len(got) != len(f) || got[22] != 1 || checksum(got[14:34]) != 0 {
		t.Fatal("group delivery TTL")
	}
	if testCodec(t, b, []Peer{{IP: a, Discovery: false}}, rules).Decode(out[0]) != nil {
		t.Fatal("local discovery opt-out ignored")
	}
	if testCodec(t, b, []Peer{{IP: a, Discovery: true, Traffic: deny}}, rules).Decode(out[0]) != nil {
		t.Fatal("receiver service ACL bypass")
	}
	if tx.Encode(udpFrame(a, dst, 27016)) != nil {
		t.Fatal("unlisted port accepted")
	}
	if tx.Encode(udpFrame(a, b, 27016)) != nil {
		t.Fatal("unicast service ACL bypass")
	}
	var limit bucket
	now := time.Unix(1, 0)
	for i := 0; i < 32; i++ {
		if !limit.take(now, 32) {
			t.Fatal("burst rejected")
		}
	}
	if limit.take(now, 32) || !limit.take(now.Add(time.Second), 32) {
		t.Fatal("bucket bounds")
	}
	// Broadcast fanout bound across the largest supported peer group.
	peers := []Peer{}
	for i := 2; i <= 65; i++ {
		peers = append(peers, Peer{IP: netip.AddrFrom4([4]byte{10, 88, 0, byte(i)}), Discovery: true})
	}
	all := testCodec(t, a, peers, rules)
	total := 0
	for i := 0; i < 3; i++ {
		total += len(all.Encode(f))
	}
	if total != 128 {
		t.Fatalf("fanout limit %d", total)
	}
}
