package path

import (
	"net"
	"net/netip"
	"testing"

	"github.com/pion/transport/v5"
)

func fixtureInterface(name string, flags net.Flags, ips ...string) *transport.Interface {
	i := transport.NewInterface(net.Interface{Name: name, Flags: flags})
	for _, ip := range ips {
		i.AddAddress(&net.IPAddr{IP: net.ParseIP(ip)})
	}
	return i
}
func TestUniqueUnderlayBudget(t *testing.T) {
	p := &ICE{Interface: "nex0", ExcludedPrefixes: []netip.Prefix{netip.MustParsePrefix("10.88.0.0/24")}}
	a := fixtureInterface("eth0", net.FlagUp, "192.0.2.10", "fe80::1", "192.0.2.10")
	ignored := []*transport.Interface{
		fixtureInterface("nex0", net.FlagUp, "10.88.0.1"),
		fixtureInterface("docker0", net.FlagUp, "172.17.0.1"),
		fixtureInterface("lo", net.FlagUp, "127.0.0.1"),
		fixtureInterface("eth2", 0, "192.0.2.11"),
		fixtureInterface("eth3", net.FlagUp, "169.254.1.2", "10.88.0.3"),
	}
	if v, ok := p.uniqueUnderlay(append(ignored, a)); !ok || v.name != "eth0" || v.addr.String() != "192.0.2.10" {
		t.Fatalf("unique underlay %+v %t", v, ok)
	}
	for _, b := range []*transport.Interface{
		fixtureInterface("eth1", net.FlagUp, "192.0.2.11"),
		fixtureInterface("eth1", net.FlagUp, "192.0.2.10"),
		fixtureInterface("eth0", net.FlagUp, "192.0.2.11"),
	} {
		if _, ok := p.uniqueUnderlay([]*transport.Interface{a, b}); ok {
			t.Fatal("ambiguous interface/address would multiply candidate sockets")
		}
	}
	if _, ok := p.uniqueUnderlay(ignored); ok {
		t.Fatal("no eligible underlay")
	}
	p.Interfaces = []string{"eth1"}
	if _, ok := p.uniqueUnderlay([]*transport.Interface{a}); ok {
		t.Fatal("interface allowlist bypass")
	}
}
