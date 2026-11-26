package protocol

import (
	"errors"
	"net/netip"
	"sort"
)

const DiscoveryProtocol = 253 // experimental inner-IP protocol, never sent on physical interfaces
const MaxDiscoveryPacket = 1200

type DiscoveryRule struct {
	Destination string `json:"destination"`
	Port        uint16 `json:"port"`
}
type DiscoveryPolicy struct {
	Rules []DiscoveryRule `json:"rules"`
}

func (p DiscoveryPolicy) Validate(cidr string) error {
	if len(p.Rules) > 16 {
		return errors.New("at most 16 discovery rules")
	}
	prefix, e := netip.ParsePrefix(cidr)
	if e != nil || !prefix.Addr().Is4() || prefix.Bits() < 24 || prefix.Bits() > 28 || prefix != prefix.Masked() {
		return errors.New("invalid discovery network")
	}
	v := prefix.Addr().As4()
	v[3] |= byte((1 << uint(32-prefix.Bits())) - 1)
	broadcast := netip.AddrFrom4(v)
	seen := map[DiscoveryRule]bool{}
	for _, r := range p.Rules {
		a, e := netip.ParseAddr(r.Destination)
		if e != nil || !a.Is4() || a.String() != r.Destination || r.Port == 0 || seen[r] {
			return errors.New("invalid discovery destination or UDP port")
		}
		// Administratively scoped IPv4 multicast only; do not bridge mDNS,
		// link-local control groups, or arbitrary public multicast.
		if a != broadcast && a != netip.MustParseAddr("255.255.255.255") && !netip.MustParsePrefix("239.0.0.0/8").Contains(a) {
			return errors.New("discovery requires network broadcast, limited broadcast, or 239/8 multicast")
		}
		seen[r] = true
	}
	return nil
}
func (p *DiscoveryPolicy) Normalize() {
	if p.Rules == nil {
		p.Rules = []DiscoveryRule{}
	}
	sort.Slice(p.Rules, func(i, j int) bool {
		a, b := p.Rules[i], p.Rules[j]
		if a.Destination == b.Destination {
			return a.Port < b.Port
		}
		return a.Destination < b.Destination
	})
}
