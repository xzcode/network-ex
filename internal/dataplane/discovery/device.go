package discovery

import (
	"github.com/xzcode/network-ex/internal/dataplane/guard"
	"github.com/xzcode/network-ex/pkg/protocol"
	"golang.zx2c4.com/wireguard/tun"
	"net/netip"
)

// The wrapper uses normal WireGuard peer encryption, AllowedIPs and path
// selection. Only validated UDP discovery payloads bypass the unicast guard;
// the authenticated source must be the exact peer overlay address.
type Device struct {
	tun.Device
	Guard   *guard.Guard
	Codec   *Codec
	pending [][]byte // WireGuard has a single TUN reader
}

func (d *Device) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	drain := func() int {
		n := 0
		for n < len(bufs) && len(d.pending) > 0 {
			p := d.pending[0]
			d.pending[0] = nil
			d.pending = d.pending[1:]
			if len(bufs[n])-offset < len(p) {
				d.Codec.Drop()
				continue
			}
			copy(bufs[n][offset:], p)
			sizes[n] = len(p)
			n++
		}
		return n
	}
	if len(d.pending) > 0 {
		if n := drain(); n > 0 {
			return n, nil
		}
	}
	n, e := d.Device.Read(bufs, sizes, offset)
	// Keep normal packets in order; use copied buffers for expanded packets.
	for i := 0; i < n; i++ {
		if sizes[i] < 1 || offset < 0 || offset+sizes[i] > len(bufs[i]) {
			sizes[i] = 0
			continue
		}
		p := bufs[i][offset : offset+sizes[i]]
		if d.Codec.IsDiscovery(p) {
			for _, v := range d.Codec.Encode(p) {
				if !d.allowDiscovery(p, netip.AddrFrom4([4]byte(v[16:20])), false) {
					d.Codec.Drop()
					continue
				}
				if len(d.pending) < 256 {
					d.pending = append(d.pending, v)
				} else {
					d.Codec.Drop()
				}
			}
			sizes[i] = 0
			continue
		}
		if len(p) > 9 && p[0]>>4 == 4 && p[9] == protocol.DiscoveryProtocol {
			d.Codec.Drop()
			sizes[i] = 0
			continue
		}
		if !d.Guard.Allow(p, false) {
			sizes[i] = 0
		}
	}
	// Do not overwrite any retained native TUN buffers during this call.
	return n, e
}
func (d *Device) Write(bufs [][]byte, offset int) (int, error) {
	allowed := make([][]byte, 0, len(bufs))
	for _, b := range bufs {
		if offset < 0 || offset >= len(b) {
			continue
		}
		p := b[offset:]
		if len(p) > 9 && p[0]>>4 == 4 && p[9] == protocol.DiscoveryProtocol {
			if inner := d.Codec.Decode(p); inner != nil && d.allowDiscovery(inner, d.Codec.Local, true) {
				v := make([]byte, offset+len(inner))
				copy(v[offset:], inner)
				allowed = append(allowed, v)
			}
			continue
		}
		if d.Guard.Allow(p, true) {
			allowed = append(allowed, b)
		}
	}
	if len(allowed) == 0 {
		return len(bufs), nil
	}
	_, e := d.Device.Write(allowed, offset)
	return len(bufs), e
}

// Establish only the corresponding permitted UDP unicast reply flow.
func (d *Device) allowDiscovery(p []byte, dst netip.Addr, inbound bool) bool {
	v := append([]byte(nil), p...)
	copy(v[16:20], dst.AsSlice())
	return d.Guard.Allow(v, inbound)
}
