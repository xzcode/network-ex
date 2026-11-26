package discovery

import (
	"encoding/binary"
	"github.com/xzcode/network-ex/pkg/protocol"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

type Peer struct {
	IP      netip.Addr
	Traffic *protocol.TrafficPolicy
}
type Stats struct {
	Sent     uint64 `json:"sent"`
	Received uint64 `json:"received"`
	Dropped  uint64 `json:"dropped"`
}
type rate struct {
	tokens float64
	at     time.Time
}

func (r *rate) take(now time.Time, perSecond, burst float64) bool {
	if r.at.IsZero() {
		r.tokens = burst
	} else {
		r.tokens += now.Sub(r.at).Seconds() * perSecond
		if r.tokens > burst {
			r.tokens = burst
		}
	}
	r.at = now
	if r.tokens < 1 {
		return false
	}
	r.tokens--
	return true
}

type Codec struct {
	Local                     netip.Addr
	rules                     map[protocol.DiscoveryRule]bool
	peers                     map[netip.Addr]*protocol.TrafficPolicy
	ordered                   []netip.Addr
	mu                        sync.Mutex
	outbound, inbound, fanout rate
	perPeer                   map[netip.Addr]*rate
	sent, received, dropped   atomic.Uint64
}

func New(local netip.Addr, rules []protocol.DiscoveryRule, peers []Peer) *Codec {
	c := &Codec{Local: local, rules: map[protocol.DiscoveryRule]bool{}, peers: map[netip.Addr]*protocol.TrafficPolicy{}, perPeer: map[netip.Addr]*rate{}}
	for _, r := range rules {
		c.rules[r] = true
	}
	for _, p := range peers {
		if p.IP != local {
			c.peers[p.IP] = p.Traffic
			c.ordered = append(c.ordered, p.IP)
			c.perPeer[p.IP] = &rate{}
		}
	}
	return c
}
func (c *Codec) Stats() Stats { return Stats{c.sent.Load(), c.received.Load(), c.dropped.Load()} }
func (c *Codec) Drop()        { c.dropped.Add(1) }
func checksum(b []byte) uint16 {
	var s uint32
	for len(b) >= 2 {
		s += uint32(binary.BigEndian.Uint16(b[:2]))
		b = b[2:]
	}
	if len(b) > 0 {
		s += uint32(b[0]) << 8
	}
	for s>>16 != 0 {
		s = (s & 0xffff) + (s >> 16)
	}
	return ^uint16(s)
}
func addr(b []byte) netip.Addr { return netip.AddrFrom4([4]byte(b)) }
func ipv4(b []byte, proto byte) bool {
	return len(b) >= 20 && b[0] == 0x45 && b[9] == proto && int(binary.BigEndian.Uint16(b[2:4])) == len(b) && binary.BigEndian.Uint16(b[6:8])&0x3fff == 0
}
func udp(b []byte) (netip.Addr, netip.Addr, uint16, bool) {
	if len(b) < 28 || len(b) > protocol.MaxDiscoveryPacket || !ipv4(b, 17) || binary.BigEndian.Uint16(b[20:22]) == 0 || int(binary.BigEndian.Uint16(b[24:26])) != len(b)-20 {
		return netip.Addr{}, netip.Addr{}, 0, false
	}
	return addr(b[12:16]), addr(b[16:20]), binary.BigEndian.Uint16(b[22:24]), true
}
func allowed(p *protocol.TrafficPolicy, port uint16) bool {
	if p == nil {
		return true
	}
	for _, s := range p.Services {
		if s.Protocol == "udp" && s.Port == port {
			return true
		}
	}
	return false
}
func (c *Codec) IsDiscovery(b []byte) bool {
	if len(b) < 20 || b[0]>>4 != 4 {
		return false
	}
	a := addr(b[16:20])
	for r := range c.rules {
		if a.String() == r.Destination {
			return true
		}
	}
	return false
}
func (c *Codec) Encode(b []byte) [][]byte {
	src, dst, port, ok := udp(b)
	if !ok || src != c.Local || !c.rules[protocol.DiscoveryRule{Destination: dst.String(), Port: port}] {
		c.Drop()
		return nil
	}
	c.mu.Lock()
	admit := c.outbound.take(time.Now(), 16, 16)
	c.mu.Unlock()
	if !admit {
		c.Drop()
		return nil
	}
	out := [][]byte{}
	// Limit each original datagram to the current authorized peer list;
	// the receiver never re-encapsulates a received discovery packet.
	for _, peer := range c.ordered {
		if !allowed(c.peers[peer], port) {
			continue
		}
		c.mu.Lock()
		ok := c.fanout.take(time.Now(), 128, 128)
		c.mu.Unlock()
		if !ok {
			c.Drop()
			break
		}
		p := make([]byte, 20+len(b))
		p[0] = 0x45
		p[8] = 1
		p[9] = protocol.DiscoveryProtocol
		binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
		copy(p[12:16], c.Local.AsSlice())
		copy(p[16:20], peer.AsSlice())
		binary.BigEndian.PutUint16(p[10:12], checksum(p[:20]))
		copy(p[20:], b)
		out = append(out, p)
		c.sent.Add(1)
	}
	return out
}
func (c *Codec) Decode(b []byte) []byte {
	if !ipv4(b, protocol.DiscoveryProtocol) || len(b) > 20+protocol.MaxDiscoveryPacket || b[8] != 1 || addr(b[16:20]) != c.Local || checksum(b[:20]) != 0 {
		c.Drop()
		return nil
	}
	from := addr(b[12:16])
	policy, exists := c.peers[from]
	src, dst, port, ok := udp(b[20:])
	if !exists || !ok || src != from || !c.rules[protocol.DiscoveryRule{Destination: dst.String(), Port: port}] || !allowed(policy, port) {
		c.Drop()
		return nil
	}
	c.mu.Lock()
	now := time.Now()
	admit := c.inbound.take(now, 128, 128) && c.perPeer[from].take(now, 16, 16)
	c.mu.Unlock()
	if !admit {
		c.Drop()
		return nil
	}
	p := append([]byte(nil), b[20:]...)
	// A received datagram is local-delivery only. TTL=1 prevents forwarding.
	p[8] = 1
	p[10] = 0
	p[11] = 0
	binary.BigEndian.PutUint16(p[10:12], checksum(p[:20]))
	c.received.Add(1)
	return p
}
