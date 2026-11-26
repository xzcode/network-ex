//go:build linux

package tun

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strings"
)

func run(args ...string) error {
	b, e := exec.Command("ip", args...).CombinedOutput()
	if e != nil {
		return fmt.Errorf("ip %v: %w (%s)", args, e, strings.TrimSpace(string(b)))
	}
	return nil
}

// Refuse to shadow non-default underlay/local routes. Do not replace routes.
func checkOverlap(name string, targets []netip.Addr) error {
	b, e := exec.Command("ip", "-4", "-j", "route", "show", "table", "all").CombinedOutput()
	if e != nil {
		return fmt.Errorf("route inspection failed: %w", e)
	}
	var routes []struct {
		Dst string `json:"dst"`
		Dev string `json:"dev"`
	}
	if e = json.Unmarshal(b, &routes); e != nil {
		return fmt.Errorf("route inspection JSON: %w", e)
	}
	for _, r := range routes {
		if r.Dst == "" || r.Dst == "default" || r.Dev == name {
			continue
		}
		prefix, e := netip.ParsePrefix(r.Dst)
		if e != nil {
			a, e := netip.ParseAddr(r.Dst)
			if e != nil {
				continue
			}
			prefix = netip.PrefixFrom(a, 32)
		}
		if prefix.Bits() == 0 {
			continue
		}
		for _, a := range targets {
			if prefix.Contains(a) {
				return fmt.Errorf("overlay address %s overlaps existing route %s on %s", a, prefix, r.Dev)
			}
		}
	}
	return nil
}

// Preflight before WireGuard can initiate traffic or create a TUN device.
func Preflight(name string, local netip.Addr, peers []netip.Addr) error {
	if _, e := net.InterfaceByName(name); e == nil {
		return fmt.Errorf("interface %s already exists", name)
	}
	return checkOverlap(name, append([]netip.Addr{local}, peers...))
}
func Configure(name string, local netip.Addr, peers []netip.Addr) error {
	if e := checkOverlap(name, append([]netip.Addr{local}, peers...)); e != nil {
		return e
	}

	if e := run("addr", "add", local.String()+"/32", "dev", name); e != nil {
		return e
	}
	if e := run("link", "set", "dev", name, "up"); e != nil {
		return e
	}
	for _, p := range peers {
		b, e := exec.Command("ip", "-4", "route", "show", "exact", p.String()+"/32").CombinedOutput()
		if e != nil {
			return fmt.Errorf("route inspection failed: %w", e)
		}
		if strings.TrimSpace(string(b)) != "" {
			return fmt.Errorf("existing exact route for %s", p)
		}
		if e = run("-4", "route", "add", p.String()+"/32", "dev", name); e != nil {
			return e
		}
	}
	return nil
}

// The Linux TUN device owns its addresses and /32 routes. Closing it removes them.
func Cleanup(name string, local netip.Addr, peers []netip.Addr) {}
