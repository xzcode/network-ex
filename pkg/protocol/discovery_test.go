package protocol

import "testing"

func TestDiscoveryPolicy(t *testing.T) {
	for _, x := range []struct {
		dst  string
		port uint16
		ok   bool
	}{
		{"10.88.0.15", 27015, true}, {"10.88.0.255", 27015, false}, {"255.255.255.255", 27015, true}, {"239.88.0.7", 27015, true}, {"224.0.0.251", 5353, false}, {"10.88.0.2", 27015, false}, {"239.88.0.7", 0, false},
	} {
		p := DiscoveryPolicy{Rules: []DiscoveryRule{{Destination: x.dst, Port: x.port}}}
		if (p.Validate("10.88.0.0/28") == nil) != x.ok {
			t.Errorf("policy result for %s:%d", x.dst, x.port)
		}
	}
	p := DiscoveryPolicy{Rules: []DiscoveryRule{{Destination: "239.88.0.7", Port: 1}, {Destination: "239.88.0.7", Port: 1}}}
	if p.Validate("10.88.0.0/24") == nil {
		t.Fatal("duplicate accepted")
	}
}
