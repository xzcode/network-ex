package managed

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/xzcode/network-ex/internal/control"
	"github.com/xzcode/network-ex/internal/dataplane/relay"
	"github.com/xzcode/network-ex/internal/dataplane/tunnel"
	"golang.org/x/crypto/curve25519"
)

type State struct {
	Server    string `json:"server"`
	CA        string `json:"ca"`
	ID        string `json:"id"`
	NetworkID string `json:"network_id"`
}
type Client struct {
	base string
	http *http.Client
}

func NewClient(server, ca string) (*Client, error) {
	u, e := url.Parse(server)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("server must be an HTTPS origin")
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if ca != "" {
		b, e := os.ReadFile(ca)
		if e != nil {
			return nil, e
		}
		p, e := x509.SystemCertPool()
		if e != nil || p == nil {
			p = x509.NewCertPool()
		}
		if !p.AppendCertsFromPEM(b) {
			return nil, errors.New("invalid CA file")
		}
		cfg.RootCAs = p
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = cfg
	return &Client{base: strings.TrimRight(u.String(), "/"), http: &http.Client{Transport: tr, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

type HTTPError struct{ Code int }

func (e HTTPError) Error() string { return fmt.Sprintf("management HTTP %d", e.Code) }
func (c *Client) post(ctx context.Context, path string, in, out any) error {
	b, e := json.Marshal(in)
	if e != nil {
		return e
	}
	r, e := http.NewRequestWithContext(ctx, "POST", c.base+path, bytes.NewReader(b))
	if e != nil {
		return e
	}
	r.Header.Set("Content-Type", "application/json")
	resp, e := c.http.Do(r)
	if e != nil {
		return e
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return HTTPError{resp.StatusCode}
	}
	b, e = io.ReadAll(io.LimitReader(resp.Body, 256*1024+1))
	if e != nil {
		return e
	}
	if len(b) > 256*1024 {
		return errors.New("management response too large")
	}
	return json.Unmarshal(b, out)
}
func readSmallSecret(path string) (string, error) { return control.PasswordFile(path) }
func writeJSON(path string, v any) error {
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".network-ex-")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if e = f.Chmod(0600); e != nil {
		f.Close()
		return e
	}
	if _, e = f.Write(append(b, '\n')); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	return os.Rename(f.Name(), path)
}
func Enroll(ctx context.Context, server, ca, inviteFile, name, dir string) (control.Device, error) {
	var d control.Device
	if name == "" || len(name) > 80 || dir == "" {
		return d, errors.New("name and new state directory required")
	}
	invite, e := readSmallSecret(inviteFile)
	if e != nil {
		return d, e
	}
	if len(invite) != 43 {
		return d, errors.New("invalid invite")
	}
	if ca != "" {
		ca, e = filepath.Abs(ca)
		if e != nil {
			return d, e
		}
	}
	c, e := NewClient(server, ca)
	if e != nil {
		return d, e
	}
	dir, e = filepath.Abs(dir)
	if e != nil {
		return d, e
	}
	if e = os.Mkdir(dir, 0700); e != nil {
		return d, fmt.Errorf("create new state directory: %w", e)
	}
	pub, identity, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return d, e
	}
	wg := make([]byte, 32)
	if _, e = rand.Read(wg); e != nil {
		return d, e
	}
	wg[0] &= 248
	wg[31] &= 127
	wg[31] |= 64
	wgPub, e := curve25519.X25519(wg, curve25519.Basepoint)
	if e != nil {
		return d, e
	}
	if e = relay.WriteSecret(filepath.Join(dir, "identity.key"), identity); e != nil {
		return d, e
	}
	if e = relay.WriteSecret(filepath.Join(dir, "wg.key"), wg); e != nil {
		return d, e
	}
	req := control.Enrollment{Invite: invite, Name: name, Identity: hex.EncodeToString(pub), WGKey: hex.EncodeToString(wgPub)}
	req.Sign(identity)
	if e = c.post(ctx, "/api/v1/devices/enroll", req, &d); e != nil {
		return d, e
	}
	if d.ID == "" || d.NetworkID == "" || d.Status != "pending" {
		return d, errors.New("invalid enrollment response")
	}
	if e = writeJSON(filepath.Join(dir, "state.json"), State{Server: c.base, CA: ca, ID: d.ID, NetworkID: d.NetworkID}); e != nil {
		return d, e
	}
	return d, nil
}
func Load(dir string) (State, error) {
	var s State
	st, e := os.Lstat(dir)
	if e != nil {
		return s, e
	}
	if !st.IsDir() || st.Mode().Perm()&0077 != 0 {
		return s, errors.New("managed state directory must be 0700")
	}
	path := filepath.Join(dir, "state.json")
	info, e := os.Lstat(path)
	if e != nil {
		return s, e
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 8192 {
		return s, errors.New("unsafe state file")
	}
	b, e := os.ReadFile(path)
	if e != nil {
		return s, e
	}
	e = json.Unmarshal(b, &s)
	if e == nil && (s.ID == "" || s.NetworkID == "") {
		e = errors.New("invalid managed state")
	}
	return s, e
}
func (c *Client) Snapshot(ctx context.Context, s State, key ed25519.PrivateKey) (control.Snapshot, error) {
	var snap control.Snapshot
	req := control.DeviceRequest{ID: s.ID}
	if e := req.Sign(key); e != nil {
		return snap, e
	}
	if e := c.post(ctx, "/api/v1/devices/snapshot", req, &snap); e != nil {
		return snap, e
	}
	now := time.Now().Unix()
	if snap.Device.ID != s.ID || snap.Device.NetworkID != s.NetworkID || snap.ValidUntil <= now || snap.ValidUntil > now+30 || len(snap.Peers) > 64 {
		return snap, errors.New("invalid or expired management snapshot")
	}
	return snap, nil
}

type Options struct {
	Dir, Interface, RelayCA string
	Port                    uint16
	ICEInterfaces           []string
}
type localStatus struct {
	State      string         `json:"state"`
	Device     control.Device `json:"device"`
	Revision   int64          `json:"revision"`
	ValidUntil int64          `json:"valid_until"`
	PeerCount  int            `json:"peer_count"`
	UpdatedAt  time.Time      `json:"updated_at"`
	Error      string         `json:"error,omitempty"`
}

func Run(ctx context.Context, o Options) error {
	var e error
	o.Dir, e = filepath.Abs(o.Dir)
	if e != nil {
		return e
	}
	state, e := Load(o.Dir)
	if e != nil {
		return e
	}
	key, e := relay.ReadHex(filepath.Join(o.Dir, "identity.key"), ed25519.PrivateKeySize, true)
	if e != nil {
		return e
	}
	c, e := NewClient(state.Server, state.CA)
	if e != nil {
		return e
	}
	lock := filepath.Join(o.Dir, "run.lock")
	f, e := os.OpenFile(lock, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return fmt.Errorf("managed agent lock: %w", e)
	}
	fmt.Fprintln(f, os.Getpid())
	f.Close()
	defer os.Remove(lock)
	runDir, e := os.MkdirTemp(o.Dir, "run-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(runDir)
	if o.RelayCA == "" {
		o.RelayCA = state.CA
	}
	var stop context.CancelFunc
	var done chan error
	var applied [32]byte
	var expiry int64
	stopTunnel := func() {
		if stop != nil {
			stop()
			<-done
			stop = nil
			done = nil
		}
		applied = [32]byte{}
		os.Remove(filepath.Join(o.Dir, "tunnel.json"))
	}
	defer stopTunnel()
	var last control.Snapshot
	status := func(mode, err string) {
		_ = writeJSON(filepath.Join(o.Dir, "managed.json"), localStatus{State: mode, Device: last.Device, Revision: last.Revision, ValidUntil: expiry, PeerCount: len(last.Peers), UpdatedAt: time.Now().UTC(), Error: err})
	}
	defer func() {
		if ctx.Err() != nil {
			status("stopped", "")
		}
	}()
	for ctx.Err() == nil {
		if done != nil {
			select {
			case err := <-done:
				stop = nil
				done = nil
				applied = [32]byte{}
				status("tunnel-error", fmt.Sprint(err))
			default:
			}
		}
		// Stop stale authorization independently of network retries; bound the next request by expiry.
		if expiry > 0 && time.Now().Unix() >= expiry {
			stopTunnel()
			status("authorization-expired", "")
		}
		reqCtx := ctx
		cancel := func() {}
		if stop != nil && expiry > time.Now().Unix() {
			reqCtx, cancel = context.WithDeadline(ctx, time.Unix(expiry, 0))
		}
		snap, err := c.Snapshot(reqCtx, state, ed25519.PrivateKey(key))
		cancel()
		if err != nil {
			var he HTTPError
			if errors.As(err, &he) && (he.Code == 401 || he.Code == 403 || he.Code == 404) {
				stopTunnel()
				expiry = 0
				status("authorization-denied", err.Error())
				return err
			}
			if expiry == 0 || time.Now().Unix() >= expiry {
				stopTunnel()
				status("authorization-expired", err.Error())
			} else {
				status("management-unreachable", err.Error())
			}
		} else {
			last = snap
			expiry = snap.ValidUntil
			if snap.Device.Status == "revoked" {
				stopTunnel()
				status("revoked", "")
				return errors.New("device revoked")
			}
			if snap.Device.Status != "approved" {
				stopTunnel()
				status("pending", "")
			} else {
				// Exclude rolling expiry and last-seen from configuration fingerprint.
				b, _ := json.Marshal(struct {
					Rev             int64
					IP, Relay, STUN string
					Peers           []control.Peer
				}{snap.Revision, snap.Device.IP, snap.RelayURL, snap.STUNURL, snap.Peers})
				hash := sha256.Sum256(b)
				if applied != hash || stop == nil {
					stopTunnel()
					cfg := tunnel.Config{Interface: o.Interface, IP: snap.Device.IP, ListenPort: o.Port, WGKeyFile: filepath.Join(o.Dir, "wg.key"), IdentityKeyFile: filepath.Join(o.Dir, "identity.key"), StatusFile: filepath.Join(o.Dir, "tunnel.json")}
					for i, p := range snap.Peers {
						tokenPath := filepath.Join(runDir, fmt.Sprintf("peer-%d.token", i))
						if e = os.WriteFile(tokenPath, []byte(p.Lease+"\n"), 0600); e != nil {
							return e
						}
						cfg.Peers = append(cfg.Peers, tunnel.Peer{IP: p.IP, PublicKey: p.WGKey, RelayURL: snap.RelayURL, RelayTokenFile: tokenPath, RelayCA: o.RelayCA, ICE: true, STUNURL: snap.STUNURL, ICEInterfaces: o.ICEInterfaces})
					}
					if e = tunnel.Check(cfg); e != nil {
						status("config-error", e.Error())
					} else {
						var child context.Context
						child, stop = context.WithCancel(ctx)
						done = make(chan error, 1)
						ch := done
						go func() { ch <- tunnel.Run(child, cfg) }()
						applied = hash
						status("applying", "")
					}
				} else {
					status("approved", "")
				}
			}
		}
		wait := 3 * time.Second
		if stop != nil && expiry > 0 {
			until := time.Until(time.Unix(expiry, 0))
			if until < wait {
				wait = until
			}
			if wait < 0 {
				wait = 0
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
	}
	return nil
}
