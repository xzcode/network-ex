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
	state, localType, remoteType                           string
	lastFailure                                            string
	localHost, localReflexive, remoteHost, remoteReflexive int
	tx, rx, attempts                                       atomic.Uint64
}

func (p *ICE) Snapshot() Snapshot {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return Snapshot{Selected: p.c != nil, State: p.state, LocalType: p.localType, RemoteType: p.remoteType, DirectTx: p.tx.Load(), DirectRx: p.rx.Load(), Attempts: p.attempts.Load(), LastFailure: p.lastFailure,
		LocalHostCandidates: p.localHost, LocalReflexiveCandidates: p.localReflexive, RemoteHostCandidates: p.remoteHost, RemoteReflexiveCandidates: p.remoteReflexive}
}
func (p *ICE) set(state string) { p.mu.Lock(); p.state = state; p.mu.Unlock() }
func (p *ICE) clear() {
	p.mu.Lock()
	p.c = nil
	p.localType = ""
	p.remoteType = ""
	p.state = "fallback"
	p.mu.Unlock()
}
func (p *ICE) Send(b []byte) error {
	p.mu.RLock()
	c := p.c
	p.mu.RUnlock()
	if c == nil {
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
		if time.Since(started) > 30*time.Second {
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
	disconnected, failed, keepalive := 4*time.Second, 8*time.Second, time.Second
	cfg := &ice.AgentConfig{NetworkTypes: []ice.NetworkType{ice.NetworkTypeUDP4}, CandidateTypes: []ice.CandidateType{ice.CandidateTypeHost, ice.CandidateTypeServerReflexive}, MulticastDNSMode: ice.MulticastDNSModeDisabled, DisconnectedTimeout: &disconnected, FailedTimeout: &failed, KeepaliveInterval: &keepalive, InterfaceFilter: p.allowedInterface, IPFilter: p.allowedIP}
	if p.STUN != "" {
		u, e := stun.ParseURI(p.STUN)
		if e != nil {
			return e
		}
		cfg.Urls = []*stun.URI{u}
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
	// Pion ICE Close is not safe to call concurrently: serialize cleanup
	// from both normal return and context cancellation.
	var closeOnce sync.Once
	closeAgent := func() { closeOnce.Do(func() { _ = a.Close() }) }
	defer closeAgent()
	stop := context.AfterFunc(ctx, closeAgent)
	defer stop()
	if e = a.OnConnectionStateChange(func(s ice.ConnectionState) {
		switch s {
		case ice.ConnectionStateDisconnected, ice.ConnectionStateFailed, ice.ConnectionStateClosed:
			cancel()
		}
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
	// Require an actually nominated pair and an additional stable interval.
	// Both relay and ICE receivers stay open during the transition.
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(2 * time.Second):
	}
	pair, e := a.GetSelectedCandidatePair()
	if e != nil || pair == nil {
		return errors.New("no nominated ICE pair")
	}
	p.mu.Lock()
	if ctx.Err() != nil {
		p.mu.Unlock()
		return ctx.Err()
	}
	p.c = c
	phase = "selected"
	p.state = "selected"
	p.lastFailure = ""
	p.localType = pair.Local.Type().String()
	p.remoteType = pair.Remote.Type().String()
	p.mu.Unlock()
	defer p.clear()
	buf := make([]byte, relay.MaxPacket)
	for {
		n, e := c.Read(buf)
		if e != nil {
			return e
		}
		if n == 0 {
			continue
		}
		p.rx.Add(uint64(n))
		deliver(append([]byte(nil), buf[:n]...))
	}
}
