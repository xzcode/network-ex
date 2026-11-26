//go:build linux

package tun

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
)

func checkSubnetOverlap(name string, targets []netip.Prefix) error {
	if len(targets) == 0 {
		return nil
	}
	b, e := exec.Command("ip", "-4", "-j", "route", "show", "table", "all").CombinedOutput()
	if e != nil {
		return fmt.Errorf("inspect routes: %w", e)
	}
	var rows []struct{ Dst, Dev string }
	if e = json.Unmarshal(b, &rows); e != nil {
		return e
	}
	for _, r := range rows {
		if r.Dst == "" || r.Dst == "default" || r.Dev == name {
			continue
		}
		p, e := netip.ParsePrefix(r.Dst)
		if e != nil {
			a, e := netip.ParseAddr(r.Dst)
			if e != nil || !a.Is4() {
				continue
			}
			p = netip.PrefixFrom(a, 32)
		}
		if p.Bits() == 0 {
			continue
		}
		for _, target := range targets {
			if p.Overlaps(target) {
				return fmt.Errorf("remote subnet %s overlaps existing route %s", target, p)
			}
		}
	}
	return nil
}
func PreflightSubnets(name string, local, remote []netip.Prefix) error {
	if e := checkSubnetOverlap(name, remote); e != nil {
		return e
	}
	if len(local) == 0 {
		return nil
	}
	b, e := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if e != nil || strings.TrimSpace(string(b)) != "1" {
		return errors.New("gateway requires administrator-enabled Linux IPv4 forwarding")
	}
	ifaces, e := net.Interfaces()
	if e != nil {
		return e
	}
	for _, p := range local {
		found := false
		for _, i := range ifaces {
			if i.Name == name || i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 || strings.HasPrefix(i.Name, "nex") || strings.HasPrefix(i.Name, "wg") || strings.HasPrefix(i.Name, "tun") {
				continue
			}
			addrs, e := i.Addrs()
			if e != nil {
				return e
			}
			for _, a := range addrs {
				q, e := netip.ParsePrefix(a.String())
				if e == nil && q.Addr().Is4() && q.Bits() <= p.Bits() && q.Masked().Contains(p.Addr()) {
					found = true
				}
			}
		}
		if !found {
			return fmt.Errorf("approved export %s is not on a connected physical interface", p)
		}
	}
	return nil
}
func ConfigureSubnets(name string, remote []netip.Prefix) error {
	if e := checkSubnetOverlap(name, remote); e != nil {
		return e
	}
	for _, p := range remote {
		if e := run("-4", "route", "add", p.String(), "dev", name); e != nil {
			return e
		}
	}
	return nil
}
