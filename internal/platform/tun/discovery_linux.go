//go:build linux

package tun

import (
	"encoding/json"
	"fmt"
	"github.com/xzcode/network-ex/pkg/protocol"
	"net/netip"
	"os/exec"
)

// Only add exact discovery routes on the overlay; never bridge a physical NIC.
func ConfigureDiscovery(name string, local netip.Addr, rules []protocol.DiscoveryRule) error {
	if len(rules) == 0 {
		return nil
	}
	if e := run("link", "set", "dev", name, "multicast", "on"); e != nil {
		return e
	}
	seen := map[string]bool{}
	for _, r := range rules {
		if seen[r.Destination] {
			continue
		}
		seen[r.Destination] = true
		a, e := netip.ParseAddr(r.Destination)
		if e != nil {
			return e
		}
		raw, e := exec.Command("ip", "-4", "-j", "route", "show", "table", "all", "exact", r.Destination+"/32").Output()
		if e != nil {
			return e
		}
		var entries []struct{ Dev string }
		if e = json.Unmarshal(raw, &entries); e != nil {
			return e
		}
		for _, v := range entries {
			if v.Dev != name {
				return fmt.Errorf("discovery destination %s already routed on another interface", a)
			}
		}
		if len(entries) > 0 {
			continue
		}
		if a.IsMulticast() {
			e = run("-4", "route", "add", r.Destination+"/32", "dev", name, "src", local.String())
		} else {
			e = run("-4", "route", "add", "broadcast", r.Destination+"/32", "dev", name, "src", local.String(), "table", "local")
		}
		if e != nil {
			return e
		}
	}
	return nil
}
