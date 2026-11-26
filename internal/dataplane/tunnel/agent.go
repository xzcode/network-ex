package tunnel

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/xzcode/network-ex/internal/dataplane/path"
	"github.com/xzcode/network-ex/internal/dataplane/relay"
	"github.com/xzcode/network-ex/internal/dataplane/transport"
	"github.com/xzcode/network-ex/internal/platform/localfile"
	platform "github.com/xzcode/network-ex/internal/platform/tun"
	"golang.zx2c4.com/wireguard/device"
	wgtun "golang.zx2c4.com/wireguard/tun"
)

type Config struct {
	Interface       string `json:"interface"`
	IP              string `json:"ip"`
	ListenPort      uint16 `json:"listen_port"`
	WGKeyFile       string `json:"wg_key_file"`
	IdentityKeyFile string `json:"identity_key_file"`
	StatusFile      string `json:"status_file"`
	Peers           []Peer `json:"peers"`
}
type Peer struct {
	IP             string   `json:"ip"`
	PublicKey      string   `json:"public_key"`
	Direct         string   `json:"direct"`
	RelayURL       string   `json:"relay_url"`
	RelayTokenFile string   `json:"relay_token_file"`
	RelayCA        string   `json:"relay_ca"`
	ICE            bool     `json:"ice"`
	STUNURL        string   `json:"stun_url"`
	ICEInterfaces  []string `json:"ice_interfaces"`
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
	State     string       `json:"state"`
	IP        string       `json:"ip"`
	UpdatedAt time.Time    `json:"updated_at"`
	Peers     []PeerStatus `json:"peers"`
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
func prepare(c Config) (netip.Addr, []transport.Peer, []netip.Addr, string, error) {
	var peers []transport.Peer
	var routes []netip.Addr
	var u strings.Builder
	bad := func(e error) (netip.Addr, []transport.Peer, []netip.Addr, string, error) {
		return netip.Addr{}, nil, nil, "", e
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
			if p.ICE {
				t.ICE = &path.ICE{Relay: t.Relay, STUN: p.STUNURL, Interface: c.Interface, Excluded: used, Interfaces: p.ICEInterfaces}
			} else if p.STUNURL != "" || len(p.ICEInterfaces) > 0 {
				return bad(errors.New("stun_url and ice_interfaces require ice=true"))
			}

		}
		peers = append(peers, t)
		routes = append(routes, a)
		fmt.Fprintf(&u, "public_key=%x\nendpoint=%s\nreplace_allowed_ips=true\nallowed_ip=%s/32\npersistent_keepalive_interval=5\n", pk, logical, a)
	}
	for _, p := range peers {
		if p.Direct.IsValid() && used[p.Direct.Addr()] {
			return bad(errors.New("direct endpoint overlaps overlay"))
		}
	}
	return ip, peers, routes, u.String(), nil
}
func Check(c Config) error {
	_, p, _, _, e := prepare(c)
	if e != nil {
		return e
	}
	_, e = transport.New(p)
	return e
}
func Run(ctx context.Context, c Config) error {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		return errors.New("unsupported platform")
	}
	ip, peers, routes, u, e := prepare(c)
	if e != nil {
		return e
	}
	b, e := transport.New(peers)
	if e != nil {
		return e
	}
	if e = platform.Preflight(c.Interface, ip, routes); e != nil {
		return e
	}
	t, e := wgtun.CreateTUN(c.Interface, 1280)
	if e != nil {
		return e
	}
	dev := device.NewDevice(t, b, device.NewLogger(device.LogLevelError, "network-ex: "))
	defer dev.Close()
	name, e := t.Name()
	if e != nil {
		return e
	}
	if name != c.Interface && !(runtime.GOOS == "darwin" && c.Interface == "utun" && regexp.MustCompile("^utun[0-9]+$").MatchString(name)) {
		return errors.New("unexpected TUN name")
	}
	defer platform.Cleanup(name, ip, routes)
	if e = dev.IpcSet(u); e != nil {
		return e
	}
	if e = platform.Configure(name, ip, routes); e != nil {
		return e
	}
	if e = dev.Up(); e != nil {
		return e
	}
	report := func(state string) error {
		if c.StatusFile == "" {
			return nil
		}
		s := Status{State: state, IP: ip.String(), UpdatedAt: time.Now().UTC()}
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
