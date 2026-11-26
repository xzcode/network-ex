//go:build linux

package tun

import (
	"fmt"
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
func Configure(name string, local netip.Addr, peers []netip.Addr) error {
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
