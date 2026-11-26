//go:build linux

package tun

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"

	"github.com/xzcode/network-ex/pkg/protocol"
	"golang.org/x/sys/unix"
	wgtun "golang.zx2c4.com/wireguard/tun"
)

type tap struct {
	f      *os.File
	name   string
	events chan wgtun.Event
	once   sync.Once
	err    error
}

var _ wgtun.Device = (*tap)(nil)

func CreateEthernet(name string) (wgtun.Device, error) {
	ifr, e := unix.NewIfreq(name)
	if e != nil {
		return nil, e
	}
	ifr.SetUint16(unix.IFF_TAP | unix.IFF_NO_PI | unix.IFF_TUN_EXCL)
	fd, e := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if e != nil {
		return nil, e
	}
	if e = unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); e != nil {
		unix.Close(fd)
		return nil, e
	}
	f := os.NewFile(uintptr(fd), "/dev/net/tun")
	if f == nil {
		unix.Close(fd)
		return nil, errors.New("cannot open TAP file")
	}
	return &tap{f: f, name: ifr.Name(), events: make(chan wgtun.Event)}, nil
}
func (t *tap) File() *os.File             { return t.f }
func (t *tap) Name() (string, error)      { return t.name, nil }
func (t *tap) MTU() (int, error)          { return 1280, nil } // enclosing WireGuard IP packet MTU
func (t *tap) Events() <-chan wgtun.Event { return t.events }
func (t *tap) BatchSize() int             { return 1 }
func (t *tap) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if len(bufs) == 0 || len(sizes) == 0 || offset < 0 || offset >= len(bufs[0]) {
		return 0, io.ErrShortBuffer
	}
	n, e := t.f.Read(bufs[0][offset:])
	sizes[0] = n
	if n > 0 {
		return 1, e
	}
	return 0, e
}
func (t *tap) Write(bufs [][]byte, offset int) (int, error) {
	for i, b := range bufs {
		if offset < 0 || offset >= len(b) {
			return i, io.ErrShortBuffer
		}
		n, e := t.f.Write(b[offset:])
		if e != nil {
			return i, e
		}
		if n != len(b)-offset {
			return i, io.ErrShortWrite
		}
	}
	return len(bufs), nil
}
func (t *tap) Close() error { t.once.Do(func() { t.err = t.f.Close(); close(t.events) }); return t.err }

func PreflightEthernet(name string, p netip.Prefix) error {
	if _, e := net.InterfaceByName(name); e == nil {
		return fmt.Errorf("interface %s already exists", name)
	}
	return checkSubnetOverlap(name, []netip.Prefix{p})
}
func ConfigureEthernet(name string, ip netip.Addr, p netip.Prefix) error {
	if e := checkSubnetOverlap(name, []netip.Prefix{p}); e != nil {
		return e
	}
	if e := run("link", "set", "dev", name, "address", protocol.VirtualMAC(ip).String(), "mtu", strconv.Itoa(protocol.EthernetMTU), "multicast", "on"); e != nil {
		return e
	}
	// Suppress IPv6 only on our new TAP when supported; IPv6 frames are also
	// rejected in the Ethernet codec regardless of OS configuration.
	f := "/proc/sys/net/ipv6/conf/" + name + "/disable_ipv6"
	if _, e := os.Stat(f); e == nil {
		if e = os.WriteFile(f, []byte("1\n"), 0644); e != nil {
			return e
		}
	}
	if e := run("-4", "addr", "add", netip.PrefixFrom(ip, p.Bits()).String(), "broadcast", "+", "dev", name); e != nil {
		return e
	}
	return run("link", "set", "dev", name, "up")
}
