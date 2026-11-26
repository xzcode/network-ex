//go:build !linux

package tun

import (
	"errors"
	"github.com/xzcode/network-ex/pkg/protocol"
	"net/netip"
)

func ConfigureDiscovery(name string, local netip.Addr, rules []protocol.DiscoveryRule) error {
	if len(rules) > 0 {
		return errors.New("game discovery is currently Linux-only")
	}
	return nil
}
