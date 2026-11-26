package protocol

import (
	"net/netip"
	"testing"
)

func TestVirtualMAC(t *testing.T) {
	ip := netip.MustParseAddr("10.88.0.2")
	if VirtualMAC(ip).String() != "02:4e:0a:58:00:02" {
		t.Fatal("MAC mapping")
	}
	if VirtualMAC(netip.MustParseAddr("::1")) != nil {
		t.Fatal("IPv6 MAC mapping")
	}
	for _, v := range []string{"10.88.0.0", "10.88.0.255", "10.89.0.2"} {
		if _, e := EthernetPrefix("10.88.0.0/24", netip.MustParseAddr(v)); e == nil {
			t.Fatalf("invalid host %s", v)
		}
	}
	if _, e := EthernetPrefix("10.88.0.0/24", ip); e != nil {
		t.Fatal(e)
	}
}
