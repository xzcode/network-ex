package protocol

import (
	"errors"
	"net/netip"
	"sort"
)

type ExitGrant struct {
	Client  string   `json:"client"`
	Gateway string   `json:"gateway"`
	Targets []string `json:"targets"`
}

// Initial egress is explicitly scoped to individual public IPv4 hosts.
// Never accept a default route or special-use address.
var excludedExit = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("224.0.0.0/3"),
}

func ValidateExitTargets(raw []string) ([]netip.Prefix, error) {
	if len(raw) > 8 {
		return nil, errors.New("maximum eight explicit exit targets")
	}
	out := []netip.Prefix{}
	seen := map[netip.Addr]bool{}
	for _, v := range raw {
		a, e := netip.ParseAddr(v)
		if e != nil || !a.Is4() || a.String() != v || !a.IsGlobalUnicast() || seen[a] {
			return nil, errors.New("exit targets must be distinct public IPv4 addresses")
		}
		for _, p := range excludedExit {
			if p.Contains(a) {
				return nil, errors.New("special-use IPv4 address is not an exit target")
			}
		}
		seen[a] = true
		out = append(out, netip.PrefixFrom(a, 32))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Addr().Less(out[j].Addr()) })
	return out, nil
}
