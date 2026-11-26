//go:build !linux

package tun

import (
	"errors"
	"net/netip"
)

func Configure(name string, local netip.Addr, peers []netip.Addr) error {
	return errors.New("M1 route integration supports Linux only")
}
