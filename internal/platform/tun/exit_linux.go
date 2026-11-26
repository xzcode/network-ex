//go:build linux

package tun

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"
)

func PreflightExit(local, remote []netip.Prefix) error {
	if len(local) == 0 {
		return nil
	}
	b, e := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if e != nil || strings.TrimSpace(string(b)) != "1" {
		return errors.New("exit gateway requires administrator-enabled IPv4 forwarding")
	}
	for _, p := range local {
		raw, e := exec.Command("ip", "-4", "-j", "route", "get", p.Addr().String()).Output()
		if e != nil {
			return fmt.Errorf("exit target %s has no route: %w", p, e)
		}
		var rs []struct{ Dev, Type string }
		if e = json.Unmarshal(raw, &rs); e != nil || len(rs) != 1 {
			return errors.New("cannot verify exit target route")
		}
		r := rs[0]
		if r.Dev == "" || r.Dev == "lo" || (r.Type != "" && r.Type != "unicast") {
			return errors.New("exit target must route to physical uplink")
		}
		for _, prefix := range []string{"nex", "tun", "tap", "wg", "utun"} {
			if strings.HasPrefix(r.Dev, prefix) {
				return errors.New("exit chaining through overlay is not allowed")
			}
		}
	}
	return nil
}
