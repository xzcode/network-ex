package protocol

import (
	"errors"
	"net/netip"
	"sort"
	"strings"
)

type ServicePort struct {
	Protocol string `json:"protocol"`
	Port     uint16 `json:"port,omitempty"`
}
type TrafficPolicy struct {
	Services []ServicePort `json:"services"`
}

func (p *TrafficPolicy) Validate() error {
	if p == nil {
		return nil
	}
	if len(p.Services) > 64 {
		return errors.New("too many allowed services")
	}
	seen := map[ServicePort]bool{}
	for _, s := range p.Services {
		if (s.Protocol != "tcp" && s.Protocol != "udp" && s.Protocol != "icmp") || (s.Protocol == "icmp" && s.Port != 0) || (s.Protocol != "icmp" && s.Port == 0) || seen[s] {
			return errors.New("invalid or duplicate service")
		}
		seen[s] = true
	}
	return nil
}
func (p *TrafficPolicy) Normalize() {
	if p != nil {
		if p.Services == nil {
			p.Services = []ServicePort{}
		}
		sort.Slice(p.Services, func(i, j int) bool {
			a, b := p.Services[i], p.Services[j]
			if a.Protocol == b.Protocol {
				return a.Port < b.Port
			}
			return a.Protocol < b.Protocol
		})
	}
}
func PrivateSubnet(raw string) (netip.Prefix, error) {
	p, e := netip.ParsePrefix(raw)
	if e != nil || !p.Addr().Is4() || p.Bits() < 16 || p != p.Masked() || !p.Addr().IsPrivate() {
		return netip.Prefix{}, errors.New("subnet must be canonical RFC1918 IPv4 /16–/32")
	}
	// Ensure the entire prefix belongs to one RFC1918 block.
	for _, v := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"} {
		b := netip.MustParsePrefix(v)
		if b.Contains(p.Addr()) && p.Bits() >= b.Bits() {
			return p, nil
		}
	}
	return netip.Prefix{}, errors.New("subnet must be entirely private")
}
func ValidateSubnets(raw []string) ([]netip.Prefix, error) {
	if len(raw) > 8 {
		return nil, errors.New("maximum eight subnets per gateway")
	}
	out := []netip.Prefix{}
	for _, v := range raw {
		p, e := PrivateSubnet(v)
		if e != nil {
			return nil, e
		}
		for _, q := range out {
			if p.Overlaps(q) {
				return nil, errors.New("overlapping subnets")
			}
		}
		out = append(out, p)
	}
	return out, nil
}
func ValidDNSLabel(s string) bool {
	if len(s) == 0 || len(s) > 63 || s != strings.ToLower(s) || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}
