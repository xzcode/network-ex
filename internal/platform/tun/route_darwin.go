//go:build darwin

package tun

import (
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"regexp"
	"sync"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

var utunName = regexp.MustCompile("^utun[0-9]*$")
var owned = struct {
	sync.Mutex
	routes map[string][]netip.Addr
}{routes: make(map[string][]netip.Addr)}

func macRun(bin string, args ...string) error {
	b, e := exec.Command(bin, args...).CombinedOutput()
	if e != nil {
		return fmt.Errorf("%s: %w (%s)", bin, e, string(b))
	}
	return nil
}
func macOverlap(name string, targets []netip.Addr) error {
	rib, e := route.FetchRIB(unix.AF_INET, route.RIBTypeRoute, 0)
	if e != nil {
		return e
	}
	ms, e := route.ParseRIB(route.RIBTypeRoute, rib)
	if e != nil {
		return e
	}
	own := 0
	if v, e := net.InterfaceByName(name); e == nil {
		own = v.Index
	}
	for _, m := range ms {
		r, ok := m.(*route.RouteMessage)
		if !ok || r.Index == own && own != 0 || len(r.Addrs) <= unix.RTAX_DST {
			continue
		}
		dst, ok := r.Addrs[unix.RTAX_DST].(*route.Inet4Addr)
		if !ok {
			continue
		}
		a := netip.AddrFrom4(dst.IP)
		bits := 32
		if len(r.Addrs) > unix.RTAX_NETMASK {
			switch mask := r.Addrs[unix.RTAX_NETMASK].(type) {
			case *route.Inet4Addr:
				n, total := net.IPMask(mask.IP[:]).Size()
				if total != 32 {
					continue
				}
				bits = n
			case nil:
				if r.Flags&unix.RTF_HOST == 0 {
					if a.IsUnspecified() {
						continue
					}
					return fmt.Errorf("unrecognized IPv4 route mask")
				}
			}
		}
		if bits == 0 {
			continue
		}
		p := netip.PrefixFrom(a, bits).Masked()
		for _, x := range targets {
			if p.Contains(x) {
				return fmt.Errorf("overlay address %s overlaps existing route %s", x, p)
			}
		}
	}
	return nil
}
func Preflight(name string, local netip.Addr, peers []netip.Addr) error {
	if !utunName.MatchString(name) {
		return fmt.Errorf("macOS interface must be utun or utunN")
	}
	if name != "utun" {
		if _, e := net.InterfaceByName(name); e == nil {
			return fmt.Errorf("interface %s already exists", name)
		}
	}
	return macOverlap(name, append([]netip.Addr{local}, peers...))
}
func Configure(name string, local netip.Addr, peers []netip.Addr) error {
	if e := macOverlap(name, append([]netip.Addr{local}, peers...)); e != nil {
		return e
	}
	if e := macRun("/sbin/ifconfig", name, "inet", local.String(), local.String(), "netmask", "255.255.255.255", "up"); e != nil {
		return e
	}
	for _, p := range peers {
		if e := macRun("/sbin/route", "-n", "add", "-host", p.String(), "-interface", name); e != nil {
			return e
		}
		owned.Lock()
		owned.routes[name] = append(owned.routes[name], p)
		owned.Unlock()
	}
	return nil
}
func Cleanup(name string, local netip.Addr, peers []netip.Addr) {
	owned.Lock()
	rs := owned.routes[name]
	delete(owned.routes, name)
	owned.Unlock()
	for _, p := range rs {
		_ = macRun("/sbin/route", "-n", "delete", "-host", p.String(), "-interface", name)
	}
}
