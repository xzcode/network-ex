package mobile

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/xzcode/network-ex/internal/control/managed"
	"github.com/xzcode/network-ex/internal/dataplane/tunnel"
	"github.com/xzcode/network-ex/internal/platform/packetqueue"
	"github.com/xzcode/network-ex/internal/platform/protect"
	wgtun "golang.zx2c4.com/wireguard/tun"
	"math"
	"net"
	"net/netip"
	"net/url"
	"path/filepath"
	"sync"
	"time"
)

// FlowPlatform integrates NEPacketTunnelFlow. ApplyTunnel waits for OS settings
// completion. BindSocket must really bind the socket to the selected underlay.
type FlowPlatform interface {
	ApplyTunnel(spec string, generation int32) bool
	WritePacket(packet []byte, generation int32) bool
	CloseTunnel(generation int32)
	BindSocket(fd int32) bool
}
type FlowSession struct {
	session    *Session
	platform   FlowPlatform
	mu         sync.Mutex
	generation int32
	current    *packetqueue.Device
}

func NewFlowSession(p FlowPlatform) *FlowSession {
	return &FlowSession{session: &Session{}, platform: p}
}
func (s *FlowSession) Start(root string) error {
	if s.platform == nil {
		return errors.New("packet flow platform required")
	}
	root, e := checkedRoot(root)
	if e != nil {
		return e
	}
	st, e := managed.Load(filepath.Join(root, "device"))
	if e != nil {
		return e
	}
	u, e := url.Parse(st.Server)
	if e != nil || u.Hostname() == "" {
		return errors.New("invalid management origin")
	}
	ext := &tunnel.External{Protect: protect.Protector(func(fd int) bool { return s.platform.BindSocket(int32(fd)) }),
		Open: func(ctx context.Context, ip netip.Addr, routes []netip.Prefix) (wgtun.Device, error) {
			resolve, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			remote, e := net.DefaultResolver.LookupNetIP(resolve, "ip4", u.Hostname())
			if e != nil || len(remote) == 0 {
				return nil, errors.New("management IPv4 address unavailable")
			}
			for _, a := range remote {
				a = a.Unmap()
				if !a.Is4() {
					return nil, errors.New("management IPv4 resolution returned another family")
				}
				if a == ip {
					return nil, errors.New("management overlaps VPN address")
				}
				for _, p := range routes {
					if p.Contains(a) {
						return nil, errors.New("management overlaps VPN route")
					}
				}
			}
			spec := tunnelSpec{Address: ip.String(), RemoteAddress: remote[0].Unmap().String(), MTU: packetqueue.MTU, Routes: []string{}}
			for _, r := range routes {
				spec.Routes = append(spec.Routes, r.String())
			}
			raw, e := json.Marshal(spec)
			if e != nil {
				return nil, e
			}
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			s.mu.Lock()
			if s.current != nil || s.generation == math.MaxInt32 {
				s.mu.Unlock()
				return nil, errors.New("packet flow generation unavailable")
			}
			s.generation++
			gen := s.generation
			var d *packetqueue.Device
			d = packetqueue.New(func(p []byte) bool {
				s.mu.Lock()
				ok := s.current == d && s.generation == gen
				s.mu.Unlock()
				return ok && s.platform.WritePacket(p, gen)
			}, func() {
				s.mu.Lock()
				if s.current == d {
					s.current = nil
				}
				s.mu.Unlock()
				s.platform.CloseTunnel(gen)
			})
			s.current = d
			s.mu.Unlock()
			if !s.platform.ApplyTunnel(string(raw), gen) {
				d.Close()
				return nil, errors.New("native packet flow settings rejected")
			}
			if ctx.Err() != nil {
				d.Close()
				return nil, ctx.Err()
			}
			return d, nil
		}}
	return s.session.startExternal(root, ext)
}
func (s *FlowSession) PushPacket(packet []byte, generation int32) bool {
	s.mu.Lock()
	d := s.current
	ok := generation == s.generation && d != nil
	s.mu.Unlock()
	return ok && d.Push(packet)
}
func (s *FlowSession) Stop()                     { s.session.Stop() }
func (s *FlowSession) WaitStopped(ms int32) bool { return s.session.WaitStopped(ms) }
func (s *FlowSession) Status() string            { return s.session.Status() }
