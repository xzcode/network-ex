//go:build !linux

package tun

import (
	"errors"
	wgtun "golang.zx2c4.com/wireguard/tun"
	"net/netip"
)

func CreateEthernet(name string) (wgtun.Device, error) {
	return nil, errors.New("Ethernet mode currently requires Linux TAP")
}
func PreflightEthernet(name string, p netip.Prefix) error {
	return errors.New("Ethernet mode currently requires Linux TAP")
}
func ConfigureEthernet(name string, ip netip.Addr, p netip.Prefix) error {
	return errors.New("Ethernet mode currently requires Linux TAP")
}
