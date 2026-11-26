package protocol

import (
	"errors"
	"net"
	"net/netip"
)

const EthernetProtocol = 252
const EthernetMTU = 1200

// Stable, locally administered unicast MAC, unique for each allocated IPv4
// address. No learning from received frames and no physical MAC disclosure.
func VirtualMAC(ip netip.Addr) net.HardwareAddr {
	if !ip.Is4() {
		return nil
	}
	a := ip.As4()
	return net.HardwareAddr{0x02, 0x4e, a[0], a[1], a[2], a[3]}
}
func EthernetPrefix(cidr string, ip netip.Addr) (netip.Prefix, error) {
	p, e := netip.ParsePrefix(cidr)
	if e != nil || !p.Addr().Is4() || p.Bits() < 24 || p.Bits() > 28 || p != p.Masked() || !p.Addr().IsPrivate() || !ip.Is4() || !p.Contains(ip) || ip == p.Addr() || !p.Contains(ip.Next()) {
		return netip.Prefix{}, errors.New("invalid Ethernet overlay prefix or host address")
	}
	return p, nil
}
