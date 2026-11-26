package tunnel

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/pion/stun"
	"github.com/xzcode/network-ex/internal/dataplane/discovery"
	"github.com/xzcode/network-ex/internal/dataplane/ethernet"
	"github.com/xzcode/network-ex/internal/dataplane/guard"
	"github.com/xzcode/network-ex/pkg/protocol"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/xzcode/network-ex/internal/dataplane/path"
	"github.com/xzcode/network-ex/internal/dataplane/relay"
	"github.com/xzcode/network-ex/internal/dataplane/transport"
	"github.com/xzcode/network-ex/internal/platform/localfile"
	"github.com/xzcode/network-ex/internal/platform/protect"
	platform "github.com/xzcode/network-ex/internal/platform/tun"
	"golang.zx2c4.com/wireguard/device"
	wgtun "golang.zx2c4.com/wireguard/tun"
)

// External is an OS-owned VPN adapter; no shell/network administration
// commands may execute when this path is selected.
type External struct {
	AllowICE bool
	Open     func(context.Context, netip.Addr, []netip.Prefix) (wgtun.Device, error)
	Protect  protect.Protector
}
type Config struct {
	External        *External                `json:"-"`
	Ethernet        bool                     `json:"-"`
	Discovery       protocol.DiscoveryPolicy `json:"-"`
	NetworkCIDR     string                   `json:"-"`
	ManagedExit     bool                     `json:"-"`
	Exports         []string                 `json:"exports,omitempty"`
	ProtectHosts    []string                 `json:"protect_hosts,omitempty"`
	Interface       string                   `json:"interface"`
	IP              string                   `json:"ip"`
	ListenPort      uint16                   `json:"listen_port"`
	WGKeyFile       string                   `json:"wg_key_file"`
	IdentityKeyFile string                   `json:"identity_key_file"`
	StatusFile      string                   `json:"status_file"`
	Peers           []Peer                   `json:"peers"`
}
type Peer struct {
	Discovery      bool                    `json:"-"`
	ExitTargets    []string                `json:"exit_targets,omitempty"`
	ExitServed     []string                `json:"exit_served,omitempty"`
	Subnets        []string                `json:"subnets,omitempty"`
	Traffic        *protocol.TrafficPolicy `json:"traffic,omitempty"`
	IP             string                  `json:"ip"`
	PublicKey      string                  `json:"public_key"`
	Direct         string                  `json:"direct"`
	RelayURL       string                  `json:"relay_url"`
	RelayTokenFile string                  `json:"relay_token_file"`
	RelayCA        string                  `json:"relay_ca"`
	ICE            bool                    `json:"ice"`
	STUNURL        string                  `json:"stun_url"`
	ICEInterfaces  []string                `json:"ice_interfaces"`
}
type PeerStatus struct {
	IP             string         `json:"ip"`
	Mode           string         `json:"mode"`
	HandshakeUnix  string         `json:"handshake_unix"`
	RxBytes        string         `json:"rx_bytes"`
	TxBytes        string         `json:"tx_bytes"`
	RelayConnected bool           `json:"relay_connected"`
	ICE            *path.Snapshot `json:"ice,omitempty"`
}
type Status struct {
	Ethernet  *ethernet.Stats  `json:"ethernet,omitempty"`
	MAC       string           `json:"mac,omitempty"`
	Discovery *discovery.Stats `json:"discovery,omitempty"`
	State     string           `json:"state"`
	IP        string           `json:"ip"`
	UpdatedAt time.Time        `json:"updated_at"`
	Peers     []PeerStatus     `json:"peers"`
}

func Load(path string) (Config, error) {
	var c Config
	f, e := os.Open(path)
	if e != nil {
		return c, e
	}
	defer f.Close()
	d := json.NewDecoder(f)
	d.DisallowUnknownFields()
	e = d.Decode(&c)
	return c, e
}
func overlay(s string) (netip.Addr, error) {
	a, e := netip.ParseAddr(s)
	if e != nil || !a.Is4() || !a.IsPrivate() {
		return netip.Addr{}, errors.New("M1 requires private IPv4 overlay address")
	}
	return a, nil
}
func scopes(c Config) ([]netip.Prefix, []netip.Prefix, []guard.Peer, error) {
	ip, e := overlay(c.IP)
	if e != nil {
		return nil, nil, nil, e
	}
	local, e := protocol.ValidateSubnets(c.Exports)
	if e != nil {
		return nil, nil, nil, e
	}
	own := []netip.Prefix{netip.PrefixFrom(ip, 32)}
	for _, p := range local {
		if p.Contains(ip) {
			return nil, nil, nil, errors.New("local export overlaps overlay address")
		}
		own = append(own, p)
	}
	remote := []netip.Prefix{}
	peers := []guard.Peer{}
	for _, p := range c.Peers {
		a, e := overlay(p.IP)
		if e != nil {
			return nil, nil, nil, e
		}
		sub, e := protocol.ValidateSubnets(p.Subnets)
		if e != nil {
			return nil, nil, nil, e
		}
		if !c.ManagedExit && (len(p.ExitTargets) > 0 || len(p.ExitServed) > 0) {
			return nil, nil, nil, errors.New("exit requires managed authorization and local opt-in")
		}
		targets, e := protocol.ValidateExitTargets(p.ExitTargets)
		if e != nil {
			return nil, nil, nil, e
		}
		served, e := protocol.ValidateExitTargets(p.ExitServed)
		if e != nil {
			return nil, nil, nil, e
		}
		sub = append(sub, targets...)
		gp := guard.Peer{Prefixes: append([]netip.Prefix{netip.PrefixFrom(a, 32)}, sub...), Policy: p.Traffic, ExitTargets: targets, ExitServed: served}
		remote = append(remote, sub...)
		peers = append(peers, gp)
	}
	if len(remote) > 64 {
		return nil, nil, nil, errors.New("too many remote subnets")
	}
	if _, e = guard.New(own, peers); e != nil {
		return nil, nil, nil, e
	}
	return own, remote, peers, nil
}
func protectUnderlay(ctx context.Context, c Config, remote []netip.Prefix) error {
	if len(remote) == 0 {
		return nil
	}
	hosts := append([]string(nil), c.ProtectHosts...)
	for _, p := range c.Peers {
		if p.Direct != "" {
			a, e := netip.ParseAddrPort(p.Direct)
			if e != nil {
				return e
			}
			hosts = append(hosts, a.Addr().String())
		}
		if p.RelayURL != "" {
			u, e := url.Parse(p.RelayURL)
			if e != nil || u.Hostname() == "" {
				return errors.New("invalid relay endpoint")
			}
			hosts = append(hosts, u.Hostname())
		}
		if p.STUNURL != "" {
			u, e := stun.ParseURI(p.STUNURL)
			if e != nil {
				return e
			}
			hosts = append(hosts, u.Host)
		}
	}
	if len(hosts) > 200 {
		return errors.New("too many protected underlay hosts")
	}
	seen := map[string]bool{}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for _, h := range hosts {
		if seen[h] {
			continue
		}
		seen[h] = true
		if h == "" {
			return errors.New("invalid protected host")
		}
		ips, e := net.DefaultResolver.LookupNetIP(ctx, "ip4", h)
		if e != nil || len(ips) == 0 {
			return fmt.Errorf("cannot verify protected host %s", h)
		}
		for _, a := range ips {
			for _, p := range remote {
				if p.Contains(a) {
					return fmt.Errorf("remote subnet %s captures underlay endpoint %s", p, h)
				}
			}
		}
	}
	return nil
}
func prepare(c Config) (netip.Addr, []transport.Peer, []netip.Addr, string, error) {
	var peers []transport.Peer
	var routes []netip.Addr
	var u strings.Builder
	bad := func(e error) (netip.Addr, []transport.Peer, []netip.Addr, string, error) {
		return netip.Addr{}, nil, nil, "", e
	}
	own, remote, _, e := scopes(c)
	if e != nil {
		return bad(e)
	}
	ip, e := overlay(c.IP)
	if e != nil {
		return bad(e)
	}
	if !regexp.MustCompile("^[A-Za-z][A-Za-z0-9_-]{0,14}$").MatchString(c.Interface) || c.ListenPort == 0 || len(c.Peers) > 64 {
		return bad(errors.New("interface, fixed listen port, and 0–64 peers required"))
	}
	key, e := relay.ReadHex(c.WGKeyFile, 32, true)
	if e != nil {
		return bad(e)
	}
	if strings.Trim(hex.EncodeToString(key), "0") == "" {
		return bad(errors.New("zero WireGuard key"))
	}
	fmt.Fprintf(&u, "private_key=%x\nlisten_port=%d\nreplace_peers=true\n", key, c.ListenPort)
	used := map[netip.Addr]bool{ip: true}
	keys := map[string]bool{}
	for _, p := range c.Peers {
		a, e := overlay(p.IP)
		if e != nil || used[a] {
			return bad(errors.New("invalid or duplicate peer IP"))
		}
		used[a] = true
		pk, e := hex.DecodeString(p.PublicKey)
		if e != nil || len(pk) != 32 || strings.Trim(hex.EncodeToString(pk), "0") == "" || keys[hex.EncodeToString(pk)] {
			return bad(errors.New("invalid or duplicate peer public key"))
		}
		keys[hex.EncodeToString(pk)] = true
		logical := netip.AddrPortFrom(a, 1)
		t := transport.Peer{Logical: logical}
		if (p.Direct == "") == (p.RelayURL == "") {
			return bad(errors.New("select exactly one path"))
		}
		if p.Direct != "" {
			if p.ICE || p.STUNURL != "" || len(p.ICEInterfaces) > 0 {
				return bad(errors.New("ICE requires relay fallback, not a static direct endpoint"))
			}
			t.Direct, e = netip.ParseAddrPort(p.Direct)
			if e != nil || t.Direct.Port() == 0 || !t.Direct.Addr().Is4() || t.Direct.Addr().IsUnspecified() || t.Direct.Addr().IsMulticast() {
				return bad(errors.New("invalid direct endpoint"))
			}
			if t.Direct.Addr() == ip {
				return bad(errors.New("physical endpoint conflicts with overlay"))
			}
		} else {
			k, e := relay.ReadHex(c.IdentityKeyFile, ed25519.PrivateKeySize, true)
			if e != nil {
				return bad(e)
			}
			if e := localfile.Check(p.RelayTokenFile, false, 4096); e != nil {
				return bad(errors.New("unsafe relay token file"))
			}
			token, e := os.ReadFile(p.RelayTokenFile)
			if e != nil {
				return bad(e)
			}
			t.Relay = &relay.Client{URL: p.RelayURL, Token: strings.TrimSpace(string(token)), CAFile: p.RelayCA, Key: ed25519.PrivateKey(k)}
			if c.External != nil {
				t.Relay.Protect = c.External.Protect
			}
			if p.ICE {
				t.ICE = &path.ICE{Relay: t.Relay, STUN: p.STUNURL, Interface: c.Interface, Excluded: used, ExcludedPrefixes: ethernetExclusions(c, remote), Interfaces: p.ICEInterfaces}
			} else if p.STUNURL != "" || len(p.ICEInterfaces) > 0 {
				return bad(errors.New("stun_url and ice_interfaces require ice=true"))
			}

		}
		peers = append(peers, t)
		routes = append(routes, a)
		fmt.Fprintf(&u, "public_key=%x\nendpoint=%s\nreplace_allowed_ips=true\nallowed_ip=%s/32\npersistent_keepalive_interval=5\n", pk, logical, a)
		for _, sub := range p.Subnets {
			fmt.Fprintf(&u, "allowed_ip=%s\n", sub)
		}
		for _, target := range p.ExitTargets {
			fmt.Fprintf(&u, "allowed_ip=%s/32\n", target)
		}

	}
	for _, p := range peers {
		if p.Direct.IsValid() {
			for _, prefix := range remote {
				if prefix.Contains(p.Direct.Addr()) {
					return bad(errors.New("direct endpoint overlaps remote subnet"))
				}
			}
			for _, prefix := range own {
				if prefix.Contains(p.Direct.Addr()) {
					return bad(errors.New("direct endpoint overlaps exported subnet"))
				}
			}
		}
		if p.Direct.IsValid() && used[p.Direct.Addr()] {
			return bad(errors.New("direct endpoint overlaps overlay"))
		}
	}
	return ip, peers, routes, u.String(), nil
}
func checkEthernet(c Config) (netip.Prefix, error) {
	if !c.Ethernet {
		return netip.Prefix{}, nil
	}
	if runtime.GOOS != "linux" {
		return netip.Prefix{}, errors.New("Ethernet mode requires Linux TAP")
	}
	if len(c.Exports) > 0 {
		return netip.Prefix{}, errors.New("Ethernet mode does not support subnet export")
	}
	a, e := overlay(c.IP)
	if e != nil {
		return netip.Prefix{}, e
	}
	p, e := protocol.EthernetPrefix(c.NetworkCIDR, a)
	if e != nil {
		return p, e
	}
	for _, v := range c.Peers {
		if len(v.Subnets)+len(v.ExitTargets)+len(v.ExitServed) > 0 {
			return p, errors.New("Ethernet mode does not support subnet or exit routes")
		}
		a, e := overlay(v.IP)
		if e != nil {
			return p, e
		}
		if _, e = protocol.EthernetPrefix(c.NetworkCIDR, a); e != nil {
			return p, e
		}
	}
	return p, c.Discovery.Validate(c.NetworkCIDR)
}
func checkExternal(c Config) error {
	if c.External == nil {
		return nil
	}
	if c.External.Open == nil || c.External.Protect == nil {
		return errors.New("native VPN open/protection callback required")
	}
	if c.Ethernet || len(c.Exports) > 0 || len(c.Discovery.Rules) > 0 {
		return errors.New("mobile VPN supports only IPv4 overlay unicast")
	}
	for _, p := range c.Peers {
		if p.Direct != "" || (p.ICE && !c.External.AllowICE) || len(p.Subnets)+len(p.ExitServed)+len(p.ExitTargets) > 0 {
			return errors.New("mobile VPN requires managed overlay peers and explicit protected ICE opt-in")
		}
	}
	return nil
}
func Check(c Config) error {
	if e := checkExternal(c); e != nil {
		return e
	}
	if _, e := checkEthernet(c); e != nil {
		return e
	}

	if len(c.Discovery.Rules) > 0 {
		if e := c.Discovery.Validate(c.NetworkCIDR); e != nil {
			return e
		}
		if runtime.GOOS != "linux" {
			return errors.New("discovery currently requires Linux")
		}
	}

	_, p, _, _, e := prepare(c)
	if e != nil {
		return e
	}
	_, e = transport.New(p)
	return e
}

var setupMu sync.Mutex

func Run(ctx context.Context, c Config) error {
	if c.External == nil && runtime.GOOS != "linux" && runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		return errors.New("unsupported platform")
	}
	if e := checkExternal(c); e != nil {
		return e
	}
	ip, peers, routes, u, e := prepare(c)
	if e != nil {
		return e
	}
	b, e := transport.New(peers)
	if e != nil {
		return e
	}
	if c.External != nil {
		b.Protect = c.External.Protect
	}
	own, remote, scopedPeers, e := scopes(c)
	if e != nil {
		return e
	}
	g, e := guard.New(own, scopedPeers)
	if e != nil {
		return e
	}
	ethPrefix, e := checkEthernet(c)
	if e != nil {
		return e
	}
	protected := ethernetExclusions(c, remote)
	if c.External != nil {
		for _, a := range routes {
			protected = append(protected, netip.PrefixFrom(a, 32))
		}
		protected = append(protected, netip.PrefixFrom(ip, 32))
	}
	if e = protectUnderlay(ctx, c, protected); e != nil {
		return e
	}
	setupMu.Lock()
	setupLocked := true
	defer func() {
		if setupLocked {
			setupMu.Unlock()
		}
	}()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	var t wgtun.Device
	if c.External != nil {
		rs := []netip.Prefix{}
		for _, a := range routes {
			rs = append(rs, netip.PrefixFrom(a, 32))
		}
		t, e = c.External.Open(ctx, ip, rs)
	} else {
		var served, targets []netip.Prefix
		for _, p := range c.Peers {
			a, _ := protocol.ValidateExitTargets(p.ExitServed)
			served = append(served, a...)
			a, _ = protocol.ValidateExitTargets(p.ExitTargets)
			targets = append(targets, a...)
		}
		if e = platform.PreflightExit(served, targets); e != nil {
			return e
		}
		if e = platform.PreflightSubnets(c.Interface, own[1:], remote); e != nil {
			return e
		}
		if c.Ethernet {
			if e = platform.PreflightEthernet(c.Interface, ethPrefix); e != nil {
				return e
			}
			t, e = platform.CreateEthernet(c.Interface)
		} else {
			if e = platform.Preflight(c.Interface, ip, routes); e != nil {
				return e
			}
			t, e = wgtun.CreateTUN(c.Interface, 1280)
		}
	}
	if e != nil {
		return e
	}
	var wrapped wgtun.Device = &guard.Device{Device: t, Guard: g}
	var codec *discovery.Codec
	var ethCodec *ethernet.Codec
	if c.Ethernet {
		ps := []ethernet.Peer{}
		for _, p := range c.Peers {
			a, _ := overlay(p.IP)
			ps = append(ps, ethernet.Peer{IP: a, Traffic: p.Traffic, Discovery: p.Discovery})
		}
		ethCodec, e = ethernet.New(ip, ethPrefix, c.Discovery.Rules, ps, g)
		if e != nil {
			t.Close()
			return e
		}
		wrapped = &ethernet.Device{Device: t, Codec: ethCodec}
	} else if len(c.Discovery.Rules) > 0 {
		if e = c.Discovery.Validate(c.NetworkCIDR); e != nil {
			t.Close()
			return e
		}
		ps := []discovery.Peer{}
		for _, p := range c.Peers {
			a, _ := overlay(p.IP)
			if p.Discovery {
				ps = append(ps, discovery.Peer{IP: a, Traffic: p.Traffic})
			}
		}
		codec = discovery.New(ip, c.Discovery.Rules, ps)
		wrapped = &discovery.Device{Device: t, Guard: g, Codec: codec}
	}
	dev := device.NewDevice(wrapped, b, device.NewLogger(device.LogLevelError, "network-ex: "))

	defer dev.Close()
	name, e := t.Name()
	if e != nil {
		return e
	}
	if name != c.Interface && !(runtime.GOOS == "darwin" && c.Interface == "utun" && regexp.MustCompile("^utun[0-9]+$").MatchString(name)) {
		return errors.New("unexpected TUN name")
	}
	if c.External == nil {
		defer platform.Cleanup(name, ip, routes)
	}
	if e = dev.IpcSet(u); e != nil {
		return e
	}
	if c.External == nil {
		if c.Ethernet {
			if e = platform.ConfigureEthernet(name, ip, ethPrefix); e != nil {
				return e
			}
		} else {
			if e = platform.Configure(name, ip, routes); e != nil {
				return e
			}
			if e = platform.ConfigureSubnets(name, remote); e != nil {
				return e
			}
		}
		if e = platform.ConfigureDiscovery(name, ip, c.Discovery.Rules); e != nil {
			return e
		}
	}
	setupMu.Unlock()
	setupLocked = false
	if e = dev.Up(); e != nil {
		return e
	}
	report := func(state string) error {
		if c.StatusFile == "" {
			return nil
		}
		s := Status{State: state, IP: ip.String(), UpdatedAt: time.Now().UTC()}
		if ethCodec != nil {
			v := ethCodec.Stats()
			s.Ethernet = &v
			s.MAC = protocol.VirtualMAC(ip).String()
		}
		if codec != nil {
			v := codec.Stats()
			s.Discovery = &v
		}
		wg, e := dev.IpcGet()
		if e != nil {
			return e
		}
		records := map[string]map[string]string{}
		var current map[string]string
		for _, line := range strings.Split(wg, "\n") {
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			if k == "public_key" {
				current = map[string]string{}
				records[v] = current
			}
			if current != nil && (k == "last_handshake_time_sec" || k == "rx_bytes" || k == "tx_bytes") {
				current[k] = v
			}
		}
		for i, p := range c.Peers {
			r := records[strings.ToLower(p.PublicKey)]
			ps := PeerStatus{IP: p.IP, Mode: "direct-configured", HandshakeUnix: r["last_handshake_time_sec"], RxBytes: r["rx_bytes"], TxBytes: r["tx_bytes"]}
			if peers[i].Relay != nil {
				ps.Mode = "relay-configured"
				ps.RelayConnected = peers[i].Relay.Ready()
				if c.External != nil {
					if ps.RelayConnected {
						ps.Mode = "relay-fallback"
					} else {
						ps.Mode = "unavailable"
					}
				}
				if peers[i].ICE != nil {
					snap := peers[i].ICE.Snapshot()
					ps.ICE = &snap
					if snap.Selected {
						ps.Mode = "ice-selected"
					} else if ps.RelayConnected {
						ps.Mode = "relay-fallback"
					} else {
						ps.Mode = "unavailable"
					}
				}

			}
			s.Peers = append(s.Peers, ps)
		}
		data, e := json.MarshalIndent(s, "", "  ")
		if e != nil {
			return e
		}
		f, e := os.CreateTemp(filepath.Dir(c.StatusFile), ".network-ex-status-")
		if e != nil {
			return e
		}
		defer os.Remove(f.Name())
		if _, e = f.Write(append(data, '\n')); e != nil {
			f.Close()
			return e
		}
		if e = f.Close(); e != nil {
			return e
		}
		return os.Rename(f.Name(), c.StatusFile)
	}
	if e = report("running"); e != nil {
		return e
	}
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return report("stopped")
		case <-dev.Wait():
			return errors.New("wireguard device stopped")
		case <-tick.C:
			if e = report("running"); e != nil {
				return e
			}
		}
	}
}

func ethernetExclusions(c Config, remote []netip.Prefix) []netip.Prefix {
	if c.Ethernet {
		if p, e := netip.ParsePrefix(c.NetworkCIDR); e == nil {
			return append(append([]netip.Prefix(nil), remote...), p)
		}
	}
	return remote
}
