package ethernet

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xzcode/network-ex/internal/dataplane/guard"
	"github.com/xzcode/network-ex/pkg/protocol"
)

const maxFrame = 14 + protocol.EthernetMTU
const arpType = 0x0806
const ipType = 0x0800

var broadcastMAC = []byte{255, 255, 255, 255, 255, 255}

type Peer struct {
	IP        netip.Addr
	Discovery bool
	Traffic   *protocol.TrafficPolicy
}
type Stats struct {
	Sent     uint64 `json:"sent"`
	Received uint64 `json:"received"`
	Dropped  uint64 `json:"dropped"`
	ARP      uint64 `json:"arp"`
	Group    uint64 `json:"group"`
}
type bucket struct {
	at     time.Time
	tokens float64
}

func (b *bucket) take(now time.Time, rate float64) bool {
	if b.at.IsZero() {
		b.tokens = rate
	} else {
		b.tokens += now.Sub(b.at).Seconds() * rate
		if b.tokens > rate {
			b.tokens = rate
		}
	}
	b.at = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

type Codec struct {
	Local                               netip.Addr
	peers                               map[netip.Addr]Peer
	ordered                             []netip.Addr
	rules                               map[protocol.DiscoveryRule]bool
	g                                   *guard.Guard
	mu                                  sync.Mutex
	out, fan, in                        bucket
	perPeer                             map[netip.Addr]*bucket
	sent, received, dropped, arp, group atomic.Uint64
}

func New(local netip.Addr, prefix netip.Prefix, rules []protocol.DiscoveryRule, peers []Peer, g *guard.Guard) (*Codec, error) {
	if _, e := protocol.EthernetPrefix(prefix.String(), local); e != nil {
		return nil, e
	}
	if g == nil || len(peers) > 64 {
		return nil, errors.New("invalid Ethernet guard or peer count")
	}
	c := &Codec{Local: local, peers: map[netip.Addr]Peer{}, rules: map[protocol.DiscoveryRule]bool{}, perPeer: map[netip.Addr]*bucket{}, g: g}
	if e := (protocol.DiscoveryPolicy{Rules: rules}).Validate(prefix.String()); e != nil {
		return nil, e
	}
	for _, r := range rules {
		c.rules[r] = true
	}
	for _, p := range peers {
		if _, e := protocol.EthernetPrefix(prefix.String(), p.IP); e != nil || p.IP == local || p.Traffic.Validate() != nil {
			return nil, errors.New("invalid Ethernet peer")
		}
		if _, ok := c.peers[p.IP]; ok {
			return nil, errors.New("duplicate Ethernet peer")
		}
		c.peers[p.IP] = p
		c.ordered = append(c.ordered, p.IP)
		c.perPeer[p.IP] = &bucket{}
	}
	return c, nil
}
func (c *Codec) Stats() Stats {
	return Stats{c.sent.Load(), c.received.Load(), c.dropped.Load(), c.arp.Load(), c.group.Load()}
}
func (c *Codec) Drop() { c.dropped.Add(1) }
func checksum(b []byte) uint16 {
	var s uint32
	for len(b) >= 2 {
		s += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) > 0 {
		s += uint32(b[0]) << 8
	}
	for s>>16 != 0 {
		s = (s & 65535) + (s >> 16)
	}
	return ^uint16(s)
}
func ip(b []byte) netip.Addr            { return netip.AddrFrom4([4]byte(b)) }
func eqMAC(b []byte, a netip.Addr) bool { return bytes.Equal(b, protocol.VirtualMAC(a)) }
func multicastMAC(a netip.Addr) net.HardwareAddr {
	v := a.As4()
	return net.HardwareAddr{1, 0, 0x5e, v[1] & 0x7f, v[2], v[3]}
}
func (c *Codec) arpFrame(f []byte, from, to netip.Addr) bool {
	// Exact Ethernet/IPv4 ARP request or reply, with all protocol and
	// hardware addresses tied to the authenticated pair. Padding is ignored.
	if len(f) < 42 || len(f) > 60 {
		return false
	}
	p := f[14:42]
	if binary.BigEndian.Uint16(p) != 1 || binary.BigEndian.Uint16(p[2:]) != ipType || p[4] != 6 || p[5] != 4 || !eqMAC(p[8:14], from) || ip(p[14:18]) != from || ip(p[24:28]) != to {
		return false
	}
	switch binary.BigEndian.Uint16(p[6:]) {
	case 1:
		return (bytes.Equal(f[:6], broadcastMAC) || eqMAC(f[:6], to)) && (bytes.Equal(p[18:24], make([]byte, 6)) || eqMAC(p[18:24], to))
	case 2:
		return eqMAC(f[:6], to) && eqMAC(p[18:24], to)
	}
	return false
}
func ipv4Frame(f []byte) ([]byte, bool) {
	if len(f) < 34 || len(f) > maxFrame || f[14] != 0x45 {
		return nil, false
	}
	p := f[14:]
	n := int(binary.BigEndian.Uint16(p[2:4]))
	if n < 20 || n > len(p) || binary.BigEndian.Uint16(p[6:8])&0x3fff != 0 || p[9] == protocol.EthernetProtocol || p[9] == protocol.DiscoveryProtocol {
		return nil, false
	}
	// Ethernet may contain minimum-frame padding; never treat it as IP data.
	if len(p) != n && len(f) > 60 {
		return nil, false
	}
	return p[:n], true
}
func (c *Codec) groupFrame(f, p []byte, peer Peer) bool {
	if !peer.Discovery || len(p) < 28 || p[9] != 17 || len(p) > protocol.MaxDiscoveryPacket {
		return false
	}
	dst := ip(p[16:20])
	port := binary.BigEndian.Uint16(p[22:24])
	if !c.rules[protocol.DiscoveryRule{Destination: dst.String(), Port: port}] || binary.BigEndian.Uint16(p[20:22]) == 0 || int(binary.BigEndian.Uint16(p[24:26])) != len(p)-20 {
		return false
	}
	if dst.IsMulticast() {
		if !bytes.Equal(f[:6], multicastMAC(dst)) {
			return false
		}
	} else if !bytes.Equal(f[:6], broadcastMAC) {
		return false
	}
	if peer.Traffic != nil {
		for _, s := range peer.Traffic.Services {
			if s.Protocol == "udp" && s.Port == port {
				return true
			}
		}
		return false
	}
	return true
}
func (c *Codec) permitGroup(p []byte, to netip.Addr, in bool) bool {
	v := append([]byte(nil), p...)
	copy(v[16:20], to.AsSlice())
	return c.g.Allow(v, in)
}
func envelope(src, dst netip.Addr, f []byte) []byte {
	p := make([]byte, 20+len(f))
	p[0] = 0x45
	p[8] = 1
	p[9] = protocol.EthernetProtocol
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	copy(p[12:16], src.AsSlice())
	copy(p[16:20], dst.AsSlice())
	binary.BigEndian.PutUint16(p[10:12], checksum(p[:20]))
	copy(p[20:], f)
	return p
}
func (c *Codec) limited(outbound bool, peer netip.Addr) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := time.Now()
	if outbound {
		return c.out.take(n, 32)
	}
	return c.in.take(n, 128) && c.perPeer[peer].take(n, 32)
}
func (c *Codec) Encode(f []byte) [][]byte {
	if len(f) < 14 || len(f) > maxFrame || !eqMAC(f[6:12], c.Local) {
		c.Drop()
		return nil
	}
	var targets []netip.Addr
	switch binary.BigEndian.Uint16(f[12:14]) {
	case arpType:
		if len(f) < 42 {
			c.Drop()
			return nil
		}
		to := ip(f[38:42])
		if _, ok := c.peers[to]; !ok || !c.arpFrame(f, c.Local, to) || !c.limited(true, to) {
			c.Drop()
			return nil
		}
		targets = append(targets, to)
		c.arp.Add(1)
	case ipType:
		p, ok := ipv4Frame(f)
		if !ok || ip(p[12:16]) != c.Local {
			c.Drop()
			return nil
		}
		to := ip(p[16:20])
		if _, ok := c.peers[to]; ok && eqMAC(f[:6], to) {
			if !c.g.Allow(p, false) {
				c.Drop()
				return nil
			}
			targets = append(targets, to)
		} else {
			if !c.limited(true, netip.Addr{}) {
				c.Drop()
				return nil
			}
			for _, a := range c.ordered {
				if !c.groupFrame(f, p, c.peers[a]) || !c.permitGroup(p, a, false) {
					continue
				}
				c.mu.Lock()
				ok := c.fan.take(time.Now(), 128)
				c.mu.Unlock()
				if !ok {
					c.Drop()
					break
				}
				targets = append(targets, a)
			}
			if len(targets) > 0 {
				c.group.Add(1)
			}
		}
	default:
		c.Drop()
		return nil
	}
	if len(targets) == 0 {
		c.Drop()
		return nil
	}
	out := make([][]byte, 0, len(targets))
	for _, to := range targets {
		out = append(out, envelope(c.Local, to, f))
		c.sent.Add(1)
	}
	return out
}
func (c *Codec) Decode(p []byte) []byte {
	if len(p) < 34 || len(p) > 20+maxFrame || p[0] != 0x45 || p[8] != 1 || p[9] != protocol.EthernetProtocol || int(binary.BigEndian.Uint16(p[2:4])) != len(p) || binary.BigEndian.Uint16(p[6:8])&0x3fff != 0 || checksum(p[:20]) != 0 || ip(p[16:20]) != c.Local {
		c.Drop()
		return nil
	}
	from := ip(p[12:16])
	peer, ok := c.peers[from]
	f := p[20:]
	if !ok || !eqMAC(f[6:12], from) {
		c.Drop()
		return nil
	}
	switch binary.BigEndian.Uint16(f[12:14]) {
	case arpType:
		if !c.arpFrame(f, from, c.Local) || !c.limited(false, from) {
			c.Drop()
			return nil
		}
		c.arp.Add(1)
	case ipType:
		inner, ok := ipv4Frame(f)
		if !ok || ip(inner[12:16]) != from {
			c.Drop()
			return nil
		}
		if ip(inner[16:20]) == c.Local && eqMAC(f[:6], c.Local) {
			if !c.g.Allow(inner, true) {
				c.Drop()
				return nil
			}
		} else {
			if !c.groupFrame(f, inner, peer) || !c.limited(false, from) || !c.permitGroup(inner, c.Local, true) {
				c.Drop()
				return nil
			}
			c.group.Add(1)
			// Local-only delivery; never bridge these frames into a physical NIC.
			f = append([]byte(nil), f...)
			f[22] = 1
			f[24] = 0
			f[25] = 0
			binary.BigEndian.PutUint16(f[24:26], checksum(f[14:34]))
		}
	default:
		c.Drop()
		return nil
	}
	c.received.Add(1)
	return f
}
