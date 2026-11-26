package transport

import (
	"context"
	"errors"
	"github.com/xzcode/network-ex/internal/platform/protect"
	"net"
	"net/netip"
	"sync"

	"github.com/xzcode/network-ex/internal/dataplane/path"
	"github.com/xzcode/network-ex/internal/dataplane/relay"
	"golang.zx2c4.com/wireguard/conn"
)

type Peer struct {
	Logical netip.AddrPort
	Direct  netip.AddrPort
	Relay   *relay.Client
	ICE     *path.ICE
}
type endpoint struct{ addr netip.AddrPort }

func (e *endpoint) ClearSrc()           {}
func (e *endpoint) SrcToString() string { return "" }
func (e *endpoint) DstToString() string { return e.addr.String() }
func (e *endpoint) DstToBytes() []byte  { b, _ := e.addr.MarshalBinary(); return b }
func (e *endpoint) DstIP() netip.Addr   { return e.addr.Addr() }
func (e *endpoint) SrcIP() netip.Addr   { return netip.Addr{} }

type packet struct {
	data     []byte
	endpoint netip.AddrPort
}
type active struct {
	sock     *net.UDPConn
	ctx      context.Context
	cancel   context.CancelFunc
	incoming chan packet
	wg       sync.WaitGroup
}
type Bind struct {
	Protect  protect.Protector
	mu       sync.RWMutex
	peers    map[netip.AddrPort]Peer
	byDirect map[netip.AddrPort]netip.AddrPort
	a        *active
	closing  bool
}

var _ conn.Bind = (*Bind)(nil)

func New(peers []Peer) (*Bind, error) {
	b := &Bind{peers: make(map[netip.AddrPort]Peer), byDirect: make(map[netip.AddrPort]netip.AddrPort)}
	for _, p := range peers {
		if !p.Logical.IsValid() || !p.Logical.Addr().Is4() || (p.Direct.IsValid() == (p.Relay != nil)) {
			return nil, errors.New("exactly one static direct/relay path per logical peer required")
		}
		if _, ok := b.peers[p.Logical]; ok {
			return nil, errors.New("duplicate peer endpoint")
		}
		if p.ICE != nil {
			if p.Relay == nil || p.ICE.Relay != p.Relay {
				return nil, errors.New("ICE requires the same relay fallback")
			}
			if e := p.ICE.Validate(); e != nil {
				return nil, e
			}
		}
		b.peers[p.Logical] = p
		if p.Direct.IsValid() {
			if !p.Direct.Addr().Is4() {
				return nil, errors.New("M1 direct IPv4 only")
			}
			if _, ok := b.byDirect[p.Direct]; ok {
				return nil, errors.New("duplicate physical endpoint")
			}
			b.byDirect[p.Direct] = p.Logical
		}
	}
	return b, nil
}
func (b *Bind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.a != nil || b.closing {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	var s *net.UDPConn
	if b.Protect != nil {
		lc := net.ListenConfig{Control: b.Protect.Control}
		pc, e := lc.ListenPacket(context.Background(), "udp4", (&net.UDPAddr{IP: net.IPv4zero, Port: int(port)}).String())
		if e != nil {
			return nil, 0, e
		}
		var ok bool
		s, ok = pc.(*net.UDPConn)
		if !ok {
			pc.Close()
			return nil, 0, errors.New("expected UDP listener")
		}
	} else {
		var e error
		s, e = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: int(port)})
		if e != nil {
			return nil, 0, e
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	a := &active{sock: s, ctx: ctx, cancel: cancel, incoming: make(chan packet, 128)}
	b.a = a
	for _, p := range b.peers {
		if p.ICE != nil {
			p := p
			a.wg.Add(1)
			go func() {
				defer a.wg.Done()
				p.ICE.Run(ctx, func(data []byte) {
					select {
					case <-ctx.Done():
					case a.incoming <- packet{data, p.Logical}:
					default:
					}
				})
			}()
		}
		if p.Relay != nil {
			p := p
			a.wg.Add(1)
			go func() {
				defer a.wg.Done()
				p.Relay.Run(ctx, func(data []byte) {
					select {
					case <-ctx.Done():
					case a.incoming <- packet{data, p.Logical}:
					default:
					}
				})
			}()
		}
	}
	direct := func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		for {
			n, src, e := s.ReadFromUDPAddrPort(bufs[0])
			if e != nil {
				if ctx.Err() != nil {
					return 0, net.ErrClosed
				}
				return 0, e
			}
			logical, ok := b.byDirect[src]
			if !ok || n == 0 {
				continue
			}
			sizes[0] = n
			eps[0] = &endpoint{logical}
			return 1, nil
		}
	}
	rel := func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		select {
		case <-ctx.Done():
			return 0, net.ErrClosed
		case p := <-a.incoming:
			if len(p.data) > len(bufs[0]) {
				sizes[0] = 0
				return 1, nil
			}
			sizes[0] = copy(bufs[0], p.data)
			eps[0] = &endpoint{p.endpoint}
			return 1, nil
		}
	}
	return []conn.ReceiveFunc{direct, rel}, uint16(s.LocalAddr().(*net.UDPAddr).Port), nil
}
func (b *Bind) Close() error {
	b.mu.Lock()
	a := b.a
	if a == nil {
		b.mu.Unlock()
		return nil
	}
	b.a = nil
	b.closing = true
	a.cancel()
	a.sock.Close()
	b.mu.Unlock()
	a.wg.Wait()
	b.mu.Lock()
	b.closing = false
	b.mu.Unlock()
	return nil
}
func (b *Bind) SetMark(mark uint32) error {
	if mark != 0 {
		return errors.New("M1 does not support fwmark")
	}
	return nil
}
func (b *Bind) BatchSize() int { return 1 }
func (b *Bind) ParseEndpoint(s string) (conn.Endpoint, error) {
	addr, e := netip.ParseAddrPort(s)
	if e != nil {
		return nil, e
	}
	if _, ok := b.peers[addr]; !ok {
		return nil, errors.New("unknown logical endpoint")
	}
	return &endpoint{addr}, nil
}
func (b *Bind) Send(bufs [][]byte, ep conn.Endpoint) error {
	e, ok := ep.(*endpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}
	p, ok := b.peers[e.addr]
	if !ok {
		return errors.New("unknown peer")
	}
	b.mu.RLock()
	a := b.a
	b.mu.RUnlock()
	if a == nil {
		return net.ErrClosed
	}
	for _, v := range bufs {
		if p.Relay != nil {
			if p.ICE != nil && p.ICE.Send(v) == nil {
				continue
			}
			if err := p.Relay.Send(v); err != nil {
				return err
			}
		} else {
			if _, err := a.sock.WriteToUDPAddrPort(v, p.Direct); err != nil {
				return err
			}
		}
	}
	return nil
}
