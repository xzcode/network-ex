//go:build !linux

package tun

import (
	"errors"
	"net/netip"
)

func PreflightExit(local, remote []netip.Prefix) error {
	if len(local)+len(remote) > 0 {
		return errors.New("selective exit routes currently require Linux")
	}
	return nil
}
