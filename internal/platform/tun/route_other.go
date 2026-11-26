//go:build !linux && !darwin && !windows

package tun

import (
	"errors"
	"net/netip"
)

func Configure(name string, local netip.Addr, peers []netip.Addr) error {
	return errors.New("M1 route integration supports Linux only")
}

func Preflight(name string, local netip.Addr, peers []netip.Addr) error {
	return errors.New("M2 route integration supports Linux only")
}

func Cleanup(name string, local netip.Addr, peers []netip.Addr) {}
