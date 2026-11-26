package path

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/stun/v4"
	"github.com/xzcode/network-ex/internal/dataplane/relay"
	"github.com/xzcode/network-ex/internal/platform/protect"
)

type Snapshot struct {
	Selected                  bool   `json:"selected"`
	State                     string `json:"state"`
	LocalType                 string `json:"local_type,omitempty"`
	RemoteType                string `json:"remote_type,omitempty"`
	DirectTx                  uint64 `json:"direct_tx_bytes"`
	DirectRx                  uint64 `json:"direct_rx_bytes"`
	Attempts                  uint64 `json:"attempts"`
	LastFailure               string `json:"last_failure,omitempty"`
	LocalHostCandidates       int    `json:"local_host_candidates"`
	LocalReflexiveCandidates  int    `json:"local_reflexive_candidates"`
	RemoteHostCandidates      int    `json:"remote_host_candidates"`
	RemoteReflexiveCandidates int    `json:"remote_reflexive_candidates"`
}
type ICE struct {
	Relay                                                  *relay.Client
	STUN                                                   string
	Interface                                              string
	Excluded                                               map[netip.Addr]bool
	ExcludedPrefixes                                       []netip.Prefix
	Interfaces                                             []string
	mu                                                     sync.RWMutex
	c                                                      *ice.Conn
	directContext                                          context.Context
	directUntil                                            time.Time
	state, localType, remoteType                           string
	lastFailure                                            string
	localHost, localReflexive, remoteHost, remoteReflexive int
	tx, rx, attempts                                       atomic.Uint64
}

func (p *ICE) directAvailable(now time.Time) bool {
	return p.c != nil && p.directContext != nil && p.directContext.Err() == nil && now.Before(p.directUntil)
}
func (p *ICE) Snapshot() Snapshot {
	p.mu.RLock()
	defer p.mu.RUnlock()
	selected := p.directAvailable(time.Now())
	state := p.state
	if state == "selected" && !selected {
		state = "fallback"
	}
	return Snapshot{Selected: selected, State: state, LocalType: p.localType, RemoteType: p.remoteType, DirectTx: p.tx.Load(), DirectRx: p.rx.Load(), Attempts: p.attempts.Load(), LastFailure: p.lastFailure,
		LocalHostCandidates: p.localHost, LocalReflexiveCandidates: p.localReflexive, RemoteHostCandidates: p.remoteHost, RemoteReflexiveCandidates: p.remoteReflexive}
}
func (p *ICE) set(state string) { p.mu.Lock(); p.state = state; p.mu.Unlock() }
func (p *ICE) clear() {
	p.mu.Lock()
	p.c = nil
	p.directContext = nil
	p.directUntil = time.Time{}
	p.localType = ""
	p.remoteType = ""
	p.state = "fallback"
	p.mu.Unlock()
}
func (p *ICE) Send(b []byte) error {
	p.mu.RLock()
	c := p.c
	ok := p.directAvailable(time.Now())
	p.mu.RUnlock()
	if !ok {
		return errors.New("ICE path unavailable")
	}
	n, e := c.Write(b)
	if e != nil {
		return e
	}
	if n != len(b) {
		return errors.New("short ICE write")
	}
	p.tx.Add(uint64(n))
	return nil
}
func (p *ICE) allowedIP(ip net.IP) bool {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	a = a.Unmap()
	for _, prefix := range p.ExcludedPrefixes {
		if prefix.Contains(a) {
			return false
		}
	}
	return a.Is4() && !a.IsUnspecified() && !a.IsLoopback() && !a.IsMulticast() && !a.IsLinkLocalUnicast() && !p.Excluded[a]
}
func (p *ICE) allowedInterface(name string) bool {
	if name == p.Interface || name == "lo" || strings.HasPrefix(name, "utun") {
		return false
	}
	if len(p.Interfaces) > 0 {
		for _, n := range p.Interfaces {
			if n == name {
				return true
			}
		}
		return false
	}
	for _, prefix := range []string{"docker", "br-", "veth", "tun", "tap", "wg", "nex"} {
		if strings.HasPrefix(name, prefix) {
			return false
		}
	}
	return true
}
func (p *ICE) Validate() error {
	if p.Relay == nil {
		return errors.New("ICE requires authenticated relay fallback")
	}
	if p.STUN != "" {
		u, e := stun.ParseURI(p.STUN)
		if e != nil || u.Scheme != stun.SchemeTypeSTUN || u.Proto != stun.ProtoTypeUDP {
			return errors.New("stun_url must be stun:host:port over UDP")
		}
	}
	if len(p.Interfaces) > 16 {
		return errors.New("too many ICE interfaces")
	}
	return nil
}
func (p *ICE) recordFailure(phase string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	switch phase {
	case "gathering", "signaling", "checking", "selected":
		p.lastFailure = phase
	default:
		p.lastFailure = "unknown"
	}
}
func (p *ICE) beginAttempt() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.state = "gathering"
	p.localHost = 0
	p.localReflexive = 0
	p.remoteHost = 0
	p.remoteReflexive = 0
}
func (p *ICE) candidate(local bool, t ice.CandidateType) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if local {
		switch t {
		case ice.CandidateTypeHost:
			p.localHost++
		case ice.CandidateTypeServerReflexive:
			p.localReflexive++
		}
	} else {
		switch t {
		case ice.CandidateTypeHost:
			p.remoteHost++
		case ice.CandidateTypeServerReflexive:
			p.remoteReflexive++
		}
	}
}
func (p *ICE) Run(ctx context.Context, deliver func([]byte)) {
	delay := time.Second
	for ctx.Err() == nil {
		p.attempts.Add(1)
		started := time.Now()
		_ = p.session(ctx, deliver)
		p.clear()
		if time.Since(started) > 30*time.Second || p.Snapshot().LastFailure == "selected" {
			delay = time.Second
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		if delay < 15*time.Second {
			delay *= 2
			if delay > 15*time.Second {
				delay = 15 * time.Second
			}
		}
	}
}
func (p *ICE) session(parent context.Context, deliver func([]byte)) (err error) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	p.beginAttempt()
	// Register after generation cleanup below (which clears the selected state).
	// Record a finite phase, never raw network errors or signaling credentials.
	phase := "gathering"
	defer func() {
		if err != nil && parent.Err() == nil {
			p.recordFailure(phase)
		}
	}()
	// A brief outage should not force a new UDP port/NAT mapping. Fall
	// back at four seconds but let ICE probe the existing authenticated
	// pair until the bounded failure timeout (4 + 24 seconds).
	disconnected, failed, keepalive := 4*time.Second, 24*time.Second, time.Second
	cfg := &ice.AgentConfig{NetworkTypes: []ice.NetworkType{ice.NetworkTypeUDP4}, CandidateTypes: []ice.CandidateType{ice.CandidateTypeHost, ice.CandidateTypeServerReflexive}, MulticastDNSMode: ice.MulticastDNSModeDisabled, DisconnectedTimeout: &disconnected, FailedTimeout: &failed, KeepaliveInterval: &keepalive, InterfaceFilter: p.allowedInterface, IPFilter: p.allowedIP}
	if p.STUN != "" {
		u, e := stun.ParseURI(p.STUN)
		if e != nil {
			return e
		}
		cfg.Urls = []*stun.URI{u}
		// Pion gathers one independent socket per configured STUN URI
		// and local address. For a single eligible underlay, use a small
		// bounded set of independent reflexive candidates. This lets
		// authenticated ICE choose among real NAT mappings rather than
		// guessing ports or relaxing the candidate/source checks.
		if candidate, ok := p.singleIPv4Underlay(); ok {
			second, third := *u, *u
			cfg.Urls = append(cfg.Urls, &second, &third)
			// Freeze the eligible interface/address for this generation.
			// If the interface changes, the next ICE attempt re-enumerates.
			cfg.InterfaceFilter = func(name string) bool { return name == candidate.name && p.allowedInterface(name) }
			cfg.IPFilter = func(ip net.IP) bool {
				a, ok := netip.AddrFromSlice(ip)
				return ok && a.Unmap() == candidate.addr && p.allowedIP(ip)
			}
		}
	}
	if p.Relay.Protect != nil {
		n, e := protect.NewICENet(p.Relay.Protect)
		if e != nil {
			return e
		}
		cfg.Net = n
	}
	a, e := ice.NewAgent(cfg)
	if e != nil {
		return e
	}
	// All per-generation state uses p.mu, including the callback and
	// publisher. A closed generation must never publish a direct path again.
	active := true
	connectedAt := time.Time{}
	everSelected := false
	deactivate := func() {
		p.mu.Lock()
		active = false
		p.directContext = nil
		p.directUntil = time.Time{}
		connectedAt = time.Time{}
		p.c = nil
		p.localType = ""
		p.remoteType = ""
		p.state = "fallback"
		p.mu.Unlock()
	}
	var closeOnce sync.Once
	closeAgent := func() { closeOnce.Do(func() { deactivate(); _ = a.GracefulClose() }) }
	defer closeAgent()
	stop := context.AfterFunc(ctx, closeAgent)
	defer stop()
	if e = a.OnConnectionStateChange(func(state ice.ConnectionState) {
		p.mu.Lock()
		if !active {
			p.mu.Unlock()
			return
		}
		switch state {
		case ice.ConnectionStateConnected, ice.ConnectionStateCompleted:
			if connectedAt.IsZero() {
				connectedAt = time.Now()
			}
		case ice.ConnectionStateDisconnected:
			// Stop direct writes immediately; relay remains open. Do not cancel
			// the ICE agent or its signal lease while the selected pair is probing.
			connectedAt = time.Time{}
			p.c = nil
			p.localType = ""
			p.remoteType = ""
			if everSelected {
				p.state = "reconnecting"
				p.lastFailure = "selected"
			}
		case ice.ConnectionStateFailed, ice.ConnectionStateClosed:
			connectedAt = time.Time{}
			p.c = nil
			p.localType = ""
			p.remoteType = ""
			p.state = "fallback"
			p.mu.Unlock()
			cancel()
			return
		default:
			connectedAt = time.Time{}
		}
		p.mu.Unlock()
	}); e != nil {
		return e
	}
	gathered := make(chan struct{})
	var gatherOnce sync.Once
	if e = a.OnCandidate(func(c ice.Candidate) {
		if c == nil {
			gatherOnce.Do(func() { close(gathered) })
		}
	}); e != nil {
		return e
	}
	if e = a.GatherCandidates(); e != nil {
		return e
	}
	select {
	case <-gathered:
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(8 * time.Second):
		return errors.New("ICE gather timeout")
	}
	frag, pwd, e := a.GetLocalUserCredentials()
	if e != nil {
		return e
	}
	cs, e := a.GetLocalCandidates()
	if e != nil {
		return e
	}
	offer := relay.Offer{Ufrag: frag, Password: pwd}
	for _, c := range cs {
		if len(offer.Candidates) >= 16 {
			break
		}
		offer.Candidates = append(offer.Candidates, c.Marshal())
		p.candidate(true, c.Type())
	}
	phase = "signaling"
	p.set("signaling")
	ws, answer, e := p.Relay.Exchange(ctx, offer)
	if e != nil {
		return e
	}
	defer ws.Close()
	// Scope authorization lasts no longer than the signed lease.
	leaseTimer := time.AfterFunc(time.Until(time.Unix(answer.Expires, 0)), cancel)
	defer leaseTimer.Stop()
	go func() { defer cancel(); ws.ReadMessage() }()

	remote := 0
	for _, raw := range answer.Offer.Candidates {
		c, e := ice.UnmarshalCandidate(raw)
		if e != nil {
			continue
		}
		if c.NetworkType() != ice.NetworkTypeUDP4 || (c.Type() != ice.CandidateTypeHost && c.Type() != ice.CandidateTypeServerReflexive) || !p.allowedIP(net.ParseIP(c.Address())) || c.Port() < 1 || c.Port() > 65535 {
			continue
		}
		if e = a.AddRemoteCandidate(c); e == nil {
			remote++
			p.candidate(false, c.Type())
		}
	}
	if remote == 0 || len(offer.Candidates) == 0 {
		return errors.New("no eligible ICE candidates")
	}
	phase = "checking"
	p.set("checking")
	check, done := context.WithTimeout(ctx, 12*time.Second)
	var c *ice.Conn
	if answer.Controlling {
		c, e = a.Dial(check, answer.Offer.Ufrag, answer.Offer.Password)
	} else {
		c, e = a.Accept(check, answer.Offer.Ufrag, answer.Offer.Password)
	}
	done()
	if e != nil {
		return e
	}
	// Publish only after the authenticated nominated pair has been
	// connected continuously for two seconds. The publisher survives short
	// disconnects and re-selects the same generation once ICE confirms liveness.
	phase = "selected"
	monitorCtx, monitorCancel := context.WithCancel(ctx)
	monitorDone := make(chan struct{})
	go func() {
		defer close(monitorDone)
		tick := time.NewTicker(200 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-monitorCtx.Done():
				return
			case <-tick.C:
			}
			p.mu.RLock()
			since := connectedAt
			ready := active && p.c == nil && !since.IsZero() && time.Since(since) >= 2*time.Second
			p.mu.RUnlock()
			if !ready {
				continue
			}
			pair, err := a.GetSelectedCandidatePair()
			if err != nil || pair == nil {
				continue
			}
			p.mu.Lock()
			if active && ctx.Err() == nil && time.Now().Unix() < answer.Expires && p.c == nil && connectedAt == since {
				p.c = c
				p.directContext = ctx
				p.directUntil = time.Unix(answer.Expires, 0)
				everSelected = true
				p.state = "selected"
				p.lastFailure = ""
				p.localType = pair.Local.Type().String()
				p.remoteType = pair.Remote.Type().String()
			}
			p.mu.Unlock()
		}
	}()
	defer func() { monitorCancel(); <-monitorDone }()
	buf := make([]byte, relay.MaxPacket)
	for {
		n, e := c.Read(buf)
		if e != nil {
			return e
		}
		if n == 0 {
			continue
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if time.Now().Unix() >= answer.Expires {
			return errors.New("ICE lease expired")
		}
		p.rx.Add(uint64(n))
		deliver(append([]byte(nil), buf[:n]...))
	}
}
