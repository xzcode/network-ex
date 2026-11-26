package guard

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/xzcode/network-ex/pkg/protocol"
)

func packet4(src, dst string, proto byte, sp, dp uint16, flags byte) []byte {
	n := 20
	switch proto {
	case 6:
		n += 20
	case 17, 1:
		n += 8
	}
	b := make([]byte, n)
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:4], uint16(n))
	b[8] = 64
	b[9] = proto
	a, c := netip.MustParseAddr(src).As4(), netip.MustParseAddr(dst).As4()
	copy(b[12:16], a[:])
	copy(b[16:20], c[:])
	switch proto {
	case 6, 17:
		binary.BigEndian.PutUint16(b[20:22], sp)
		binary.BigEndian.PutUint16(b[22:24], dp)
		if proto == 6 {
			b[32] = 0x50
			b[33] = flags
		} else {
			binary.BigEndian.PutUint16(b[24:26], 8)
		}
	case 1:
		b[20] = flags
		binary.BigEndian.PutUint16(b[24:26], sp)
	}
	return b
}
func TestGuardStatefulPolicyAndScope(t *testing.T) {
	g, e := New([]netip.Prefix{netip.MustParsePrefix("10.88.0.2/32"), netip.MustParsePrefix("192.168.77.0/24")}, []Peer{
		{Prefixes: []netip.Prefix{netip.MustParsePrefix("10.88.0.1/32")}, Policy: &protocol.TrafficPolicy{Services: []protocol.ServicePort{{Protocol: "tcp", Port: 443}, {Protocol: "udp", Port: 53}, {Protocol: "icmp"}}}},
		{Prefixes: []netip.Prefix{netip.MustParsePrefix("10.88.0.3/32")}},
	})
	if e != nil {
		t.Fatal(e)
	}
	local, remote := "192.168.77.2", "10.88.0.1"
	test := func(name string, packet []byte, in, want bool) {
		t.Helper()
		if g.Allow(packet, in) != want {
			t.Errorf("%s: want %v", name, want)
		}
	}
	test("unsolicited allowed source port", packet4(remote, local, 6, 443, 55555, 0x10), true, false)
	test("wrong port", packet4(remote, local, 6, 55555, 22, 2), true, false)
	test("allowed SYN", packet4(remote, local, 6, 55555, 443, 2), true, true)
	test("response", packet4(local, remote, 6, 443, 55555, 0x12), false, true)
	test("request data", packet4(remote, local, 6, 55555, 443, 0x18), true, true)
	test("unrelated destination", packet4(remote, "192.168.78.2", 6, 55555, 443, 2), true, false)
	test("unauthorized LAN source", packet4("192.168.78.2", remote, 6, 443, 55555, 0x10), false, false)
	test("cross-peer forwarding", packet4("10.88.0.3", remote, 6, 55555, 443, 2), false, false)
	test("UDP unsolicited response", packet4(local, remote, 17, 53, 45678, 0), false, false)
	test("UDP request", packet4(remote, local, 17, 45678, 53, 0), true, true)
	test("UDP reply", packet4(local, remote, 17, 53, 45678, 0), false, true)
	test("ICMP echo unsolicited reply", packet4(local, remote, 1, 17, 0, 0), false, false)
	test("ICMP echo request", packet4(remote, local, 1, 17, 0, 8), true, true)
	test("ICMP echo reply", packet4(local, remote, 1, 17, 0, 0), false, true)
	f := packet4(remote, local, 6, 55556, 443, 2)
	f[6] = 0x20
	test("fragment", f, true, false)
	f = packet4(remote, local, 6, 55556, 443, 2)
	f[0] = 0x46
	test("IP option", f, true, false)
	if _, e = New([]netip.Prefix{netip.MustParsePrefix("10.88.0.1/32")}, []Peer{{Prefixes: []netip.Prefix{netip.MustParsePrefix("10.88.0.0/24")}}}); e == nil {
		t.Fatal("accepted ambiguous address ownership")
	}
}
