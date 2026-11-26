//go:build !linux

package tun

import (
	"errors"
	"net/netip"
)

func PreflightSubnets(name string, local, remote []netip.Prefix) error {
	if len(local)+len(remote) > 0 {
		return errors.New("subnet routing is currently Linux-only")
	}
	return nil
}
func ConfigureSubnets(name string, remote []netip.Prefix) error {
	if len(remote) > 0 {
		return errors.New("subnet routing is currently Linux-only")
	}
	return nil
}
