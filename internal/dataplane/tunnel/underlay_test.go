package tunnel

import (
	"context"
	"net/netip"
	"testing"
)

func TestUnderlayIPv4LiteralOverlap(t *testing.T) {
	c := Config{ProtectHosts: []string{"10.88.0.2"}}
	if e := protectUnderlay(context.Background(), c, []netip.Prefix{netip.MustParsePrefix("10.88.0.2/32")}); e == nil {
		t.Fatal("IPv4 literal escaped underlay route conflict check")
	}
	if e := protectUnderlay(context.Background(), c, []netip.Prefix{netip.MustParsePrefix("10.88.0.3/32")}); e != nil {
		t.Fatal(e)
	}
}
