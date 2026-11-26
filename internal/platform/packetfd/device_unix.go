//go:build !windows

package packetfd

import (
	"errors"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"
	"io"
	"os"
	"sync"
)

// Owns a detached, raw IP packet file descriptor. The platform must transfer
// ownership exactly once; closing the device tears down its VPN interface.
type Device struct {
	f      *os.File
	name   string
	events chan tun.Event
	once   sync.Once
	err    error
}

var _ tun.Device = (*Device)(nil)

func New(fd int, name string) (*Device, error) {
	if fd < 0 {
		return nil, errors.New("VPN interface not established")
	}
	if e := unix.SetNonblock(fd, true); e != nil {
		unix.Close(fd)
		return nil, e
	}
	unix.CloseOnExec(fd)
	f := os.NewFile(uintptr(fd), "network-ex-vpn")
	if f == nil {
		unix.Close(fd)
		return nil, errors.New("invalid VPN descriptor")
	}
	return &Device{f: f, name: name, events: make(chan tun.Event)}, nil
}
func (d *Device) File() *os.File           { return d.f }
func (d *Device) Name() (string, error)    { return d.name, nil }
func (d *Device) MTU() (int, error)        { return 1280, nil }
func (d *Device) Events() <-chan tun.Event { return d.events }
func (d *Device) BatchSize() int           { return 1 }
func (d *Device) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if len(bufs) == 0 || len(sizes) == 0 || offset < 0 || offset >= len(bufs[0]) {
		return 0, io.ErrShortBuffer
	}
	n, e := d.f.Read(bufs[0][offset:])
	sizes[0] = n
	if n > 0 {
		return 1, e
	}
	return 0, e
}
func (d *Device) Write(bufs [][]byte, offset int) (int, error) {
	for i, b := range bufs {
		if offset < 0 || offset >= len(b) {
			return i, io.ErrShortBuffer
		}
		n, e := d.f.Write(b[offset:])
		if e != nil {
			return i, e
		}
		if n != len(b)-offset {
			return i, io.ErrShortWrite
		}
	}
	return len(bufs), nil
}
func (d *Device) Close() error {
	d.once.Do(func() { d.err = d.f.Close(); close(d.events) })
	return d.err
}
