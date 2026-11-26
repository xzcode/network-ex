package ethernet

import (
	"golang.zx2c4.com/wireguard/tun"
	"io"
)

// A TAP produces Ethernet frames, while WireGuard expects IP packets.
// Translate only validated frames into bounded per-peer IPv4 envelopes.
type Device struct {
	tun.Device
	Codec   *Codec
	pending [][]byte
	scratch []byte
}

func (d *Device) BatchSize() int { return 1 }
func (d *Device) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if len(bufs) == 0 || len(sizes) == 0 || offset < 0 || offset >= len(bufs[0]) {
		return 0, io.ErrShortBuffer
	}
	if d.scratch == nil {
		d.scratch = make([]byte, 2048)
	}
	for {
		if len(d.pending) > 0 {
			p := d.pending[0]
			d.pending[0] = nil
			d.pending = d.pending[1:]
			if len(p) > len(bufs[0])-offset {
				d.Codec.Drop()
				continue
			}
			copy(bufs[0][offset:], p)
			sizes[0] = len(p)
			return 1, nil
		}
		var ns [1]int
		n, e := d.Device.Read([][]byte{d.scratch}, ns[:], 0)
		if e != nil {
			return 0, e
		}
		if n != 1 || ns[0] < 1 || ns[0] > len(d.scratch) {
			continue
		}
		d.pending = d.Codec.Encode(d.scratch[:ns[0]])
	}
}
func (d *Device) Write(bufs [][]byte, offset int) (int, error) {
	for i, b := range bufs {
		if offset < 0 || offset >= len(b) {
			d.Codec.Drop()
			continue
		}
		f := d.Codec.Decode(b[offset:])
		if f == nil {
			continue
		}
		if _, e := d.Device.Write([][]byte{f}, 0); e != nil {
			return i, e
		}
	}
	return len(bufs), nil
}
