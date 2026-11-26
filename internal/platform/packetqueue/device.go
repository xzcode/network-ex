package packetqueue

import (
	"encoding/binary"
	"errors"
	"golang.zx2c4.com/wireguard/tun"
	"io"
	"os"
	"sync"
	"sync/atomic"
)

const MTU = 1280
const Capacity = 256

// Device adapts a packet-flow API to wireguard-go. Buffers are copied
// across ownership boundaries; queue saturation drops rather than blocks.
type Device struct {
	mu          sync.Mutex
	closed      bool
	queue       chan []byte
	done        chan struct{}
	events      chan tun.Event
	write       func([]byte) bool
	closeNative func()
	once        sync.Once
	drops       atomic.Uint64
}

var _ tun.Device = (*Device)(nil)

func New(write func([]byte) bool, closeNative func()) *Device {
	return &Device{queue: make(chan []byte, Capacity), done: make(chan struct{}), events: make(chan tun.Event), write: write, closeNative: closeNative}
}
func valid(b []byte) bool {
	return len(b) >= 20 && len(b) <= MTU && b[0] == 0x45 && int(binary.BigEndian.Uint16(b[2:4])) == len(b) && binary.BigEndian.Uint16(b[6:8])&0x3fff == 0
}
func (d *Device) Push(b []byte) bool {
	if !valid(b) {
		d.drops.Add(1)
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return false
	}
	select {
	case d.queue <- append([]byte(nil), b...):
		return true
	default:
		d.drops.Add(1)
		return false
	}
}
func (d *Device) Drops() uint64            { return d.drops.Load() }
func (d *Device) File() *os.File           { return nil }
func (d *Device) Name() (string, error)    { return "mobile0", nil }
func (d *Device) MTU() (int, error)        { return MTU, nil }
func (d *Device) Events() <-chan tun.Event { return d.events }
func (d *Device) BatchSize() int           { return 1 }
func (d *Device) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if len(bufs) == 0 || len(sizes) == 0 || offset < 0 || offset >= len(bufs[0]) {
		return 0, io.ErrShortBuffer
	}
	select {
	case <-d.done:
		return 0, os.ErrClosed
	default:
	}
	select {
	case <-d.done:
		return 0, os.ErrClosed
	case p := <-d.queue:
		select {
		case <-d.done:
			return 0, os.ErrClosed
		default:
		}
		if len(bufs[0])-offset < len(p) {
			return 0, io.ErrShortBuffer
		}
		copy(bufs[0][offset:], p)
		sizes[0] = len(p)
		return 1, nil
	}
}
func (d *Device) Write(bufs [][]byte, offset int) (int, error) {
	for i, b := range bufs {
		if offset < 0 || offset >= len(b) {
			return i, io.ErrShortBuffer
		}
		select {
		case <-d.done:
			return i, os.ErrClosed
		default:
		}
		p := b[offset:]
		if !valid(p) {
			d.drops.Add(1)
			continue
		}
		if d.write == nil {
			return i, errors.New("no native packet writer")
		}
		if !d.write(append([]byte(nil), p...)) {
			d.drops.Add(1)
		}
	}
	return len(bufs), nil
}
func (d *Device) Close() error {
	d.once.Do(func() {
		d.mu.Lock()
		d.closed = true
		close(d.done)
		close(d.events)
		for len(d.queue) > 0 {
			select {
			case <-d.queue:
			default:
			}
		}
		d.mu.Unlock()
		if d.closeNative != nil {
			d.closeNative()
		}
	})
	return nil
}
