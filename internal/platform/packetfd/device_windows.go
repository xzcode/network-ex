//go:build windows

package packetfd

import (
	"errors"
	"golang.zx2c4.com/wireguard/tun"
)

func New(fd int, name string) (tun.Device, error) {
	return nil, errors.New("native VPN descriptors are unavailable on Windows")
}
