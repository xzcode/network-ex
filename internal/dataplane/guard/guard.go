package guard

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
	"time"

	"github.com/xzcode/network-ex/pkg/protocol"
	"golang.zx2c4.com/wireguard/tun"
)

type Peer struct {
	ExitTargets []netip.Prefix
	ExitServed  []netip.Prefix
	Prefixes    []netip.Prefix
	Policy      *protocol.TrafficPolicy
}
type flow struct {
	src, dst netip.Addr
	proto    byte
	sp, dp   uint16
}

func (f flow) reverse() flow { return flow{f.dst, f.src, f.proto, f.dp, f.sp} }

type packet struct {
	flow
	syn, ack, fin, rst bool
	icmpType           byte
}
type Guard struct {
	local     []netip.Prefix
	peers     []Peer
	mu        sync.Mutex
	flows     map[flow]time.Time
	lastSweep time.Time
}

func New(local []netip.Prefix, peers []Peer) (*Guard, error) {
	if len(local) == 0 {
		return nil, errors.New("empty local address scope")
	}
	all := append([]netip.Prefix(nil), local...)
	served := map[netip.Prefix]bool{}
	hasTargets := false
	for _, p := range peers {
		if len(p.ExitTargets) > 0 {
			hasTargets = true
		}
		for _, v := range p.ExitServed {
			if served[v] {
				continue
			}
			for _, q := range all {
				if v.Overlaps(q) {
					return nil, errors.New("exit served scope overlaps local scope")
				}
			}
			served[v] = true
			all = append(all, v)
		}
	}
	if hasTargets && len(served) > 0 {
		return nil, errors.New("exit chaining is not supported")
	}

	for _, p := range peers {
		if len(p.Prefixes) == 0 || p.Policy.Validate() != nil {
			return nil, errors.New("invalid peer scope or policy")
		}
		for _, v := range p.Prefixes {
			for _, q := range all {
				if v.Overlaps(q) {
					return nil, errors.New("ambiguous overlay address ownership")
				}
			}
			all = append(all, v)
		}
	}
	return &Guard{local: local, peers: peers, flows: make(map[flow]time.Time)}, nil
}
func contains(ps []netip.Prefix, a netip.Addr) bool {
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
func parse(b []byte) (packet, bool) {
	var p packet
	// IPv4 only. No IP options or fragmented packets: never parse a port
	// from an arbitrary fragment and never allow IP source-routing options.
	if len(b) < 20 || b[0] != 0x45 {
		return p, false
	}
	size := int(binary.BigEndian.Uint16(b[2:4]))
	if size < 20 || size > len(b) || binary.BigEndian.Uint16(b[6:8])&0x3fff != 0 {
		return p, false
	}
	p.src = netip.AddrFrom4([4]byte(b[12:16]))
	p.dst = netip.AddrFrom4([4]byte(b[16:20]))
	p.proto = b[9]
	v := b[20:size]
	switch p.proto {
	case 6:
		if len(v) < 20 || int(v[12]>>4)*4 < 20 || int(v[12]>>4)*4 > len(v) {
			return p, false
		}
		p.sp = binary.BigEndian.Uint16(v[:2])
		p.dp = binary.BigEndian.Uint16(v[2:4])
		if p.sp == 0 || p.dp == 0 {
			return p, false
		}
		p.fin = v[13]&1 != 0
		p.syn = v[13]&2 != 0
		p.rst = v[13]&4 != 0
		p.ack = v[13]&16 != 0
	case 17:
		if len(v) < 8 || int(binary.BigEndian.Uint16(v[4:6])) != len(v) {
			return p, false
		}
		p.sp = binary.BigEndian.Uint16(v[:2])
		p.dp = binary.BigEndian.Uint16(v[2:4])
		if p.sp == 0 || p.dp == 0 {
			return p, false
		}
	case 1:
		if len(v) < 8 {
			return p, false
		}
		p.icmpType = v[0]
		p.sp = binary.BigEndian.Uint16(v[4:6])
		p.dp = p.sp
	}
	return p, true
}
func allowedService(policy *protocol.TrafficPolicy, p packet) bool {
	for _, s := range policy.Services {
		switch p.proto {
		case 6:
			if s.Protocol == "tcp" && s.Port == p.dp && p.syn && !p.ack && !p.rst && !p.fin {
				return true
			}
		case 17:
			if s.Protocol == "udp" && s.Port == p.dp {
				return true
			}
		case 1:
			if s.Protocol == "icmp" && p.icmpType == 8 {
				return true
			}
		}
	}
	return false
}
func (g *Guard) Allow(b []byte, inbound bool) bool {
	p, ok := parse(b)
	if !ok || p.proto == protocol.DiscoveryProtocol || p.proto == protocol.EthernetProtocol {
		return false
	}
	local, remote := p.src, p.dst
	if inbound {
		local, remote = p.dst, p.src
	}

	var selected *Peer
	for i := range g.peers {
		if contains(g.peers[i].Prefixes, remote) {
			selected = &g.peers[i]
			break
		}
	}
	if selected == nil {
		return false
	}
	exitLocal := contains(selected.ExitServed, local)
	exitRemote := contains(selected.ExitTargets, remote)
	if !contains(g.local, local) && !exitLocal {
		return false
	}
	exit := exitLocal || exitRemote
	if selected.Policy == nil && !exit {
		return true
	}
	// State is per normalized flow and shared by ingress and egress. Unknown
	// reverse packets do not gain access merely by using an allowed source port.
	if p.proto != 6 && p.proto != 17 && p.proto != 1 {
		return false
	}
	if p.proto == 1 && p.icmpType != 0 && p.icmpType != 8 {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	if now.Sub(g.lastSweep) > time.Second {
		for k, v := range g.flows {
			if !now.Before(v) {
				delete(g.flows, k)
			}
		}
		g.lastSweep = now
	}
	f := p.flow
	key := f
	forward := true
	until, exists := g.flows[f]
	if !exists || !now.Before(until) {
		key = f.reverse()
		until, exists = g.flows[key]
		forward = false
	}
	if exists && now.Before(until) {
		if p.proto == 1 && ((forward && p.icmpType != 8) || (!forward && p.icmpType != 0)) {
			return false
		}
		if p.proto == 6 && p.syn && !p.ack && !forward {
			return false
		}
		if p.proto == 6 && p.rst {
			delete(g.flows, key)
		} else {
			ttl := 2 * time.Minute
			if p.proto == 6 {
				ttl = 10 * time.Minute
				if p.fin {
					ttl = 30 * time.Second
				}
			}
			g.flows[key] = now.Add(ttl)
		}
		return true
	}
	if exit && !((exitRemote && !inbound) || (exitLocal && inbound)) {
		return false
	}
	allowed := false
	if selected.Policy != nil {
		allowed = allowedService(selected.Policy, p)
	} else {
		allowed = p.proto == 17 || (p.proto == 6 && p.syn && !p.ack && !p.fin && !p.rst) || (p.proto == 1 && p.icmpType == 8)
	}
	if !allowed || len(g.flows) >= 8192 {
		return false
	}
	ttl := 2 * time.Minute
	if p.proto == 6 {
		ttl = 10 * time.Minute
	}
	g.flows[f] = now.Add(ttl)
	return true
}

type Device struct {
	tun.Device
	Guard *Guard
}

func (d *Device) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	n, e := d.Device.Read(bufs, sizes, offset)
	for i := 0; i < n; i++ {
		if sizes[i] < 1 || offset < 0 || offset+sizes[i] > len(bufs[i]) || !d.Guard.Allow(bufs[i][offset:offset+sizes[i]], false) {
			sizes[i] = 0
		}
	}
	return n, e
}
func (d *Device) Write(bufs [][]byte, offset int) (int, error) {
	allowed := make([][]byte, 0, len(bufs))
	for _, b := range bufs {
		if offset >= 0 && offset < len(b) && d.Guard.Allow(b[offset:], true) {
			allowed = append(allowed, b)
		}
	}
	if len(allowed) == 0 {
		return len(bufs), nil
	}
	_, e := d.Device.Write(allowed, offset)
	return len(bufs), e
}
