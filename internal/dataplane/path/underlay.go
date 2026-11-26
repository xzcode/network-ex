package path

import (
	"net"
	"net/netip"

	"github.com/pion/transport/v5"
	"github.com/pion/transport/v5/stdnet"
)

type underlayAddress struct {
	name string
	addr netip.Addr
}

// Redundant gathering is limited to a single eligible interface/address.
// On multi-interface devices retain ordinary Pion gathering.
func (p *ICE) singleIPv4Underlay() (underlayAddress, bool) {
	n, e := stdnet.NewNet()
	if e != nil {
		return underlayAddress{}, false
	}
	ifs, e := n.Interfaces()
	if e != nil {
		return underlayAddress{}, false
	}
	return p.uniqueUnderlay(ifs)
}
func (p *ICE) uniqueUnderlay(ifs []*transport.Interface) (underlayAddress, bool) {
	var only underlayAddress
	for _, i := range ifs {
		if i == nil || i.Flags&net.FlagUp == 0 || !p.allowedInterface(i.Name) {
			continue
		}
		as, e := i.Addrs()
		if e != nil {
			continue
		}
		for _, a := range as {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			default:
				continue
			}
			if !p.allowedIP(ip) {
				continue
			}
			v, ok := netip.AddrFromSlice(ip)
			if !ok {
				continue
			}
			candidate := underlayAddress{i.Name, v.Unmap()}
			if only.addr.IsValid() && only != candidate {
				return underlayAddress{}, false
			}
			only = candidate
		}
	}
	return only, only.addr.Is4()
}
