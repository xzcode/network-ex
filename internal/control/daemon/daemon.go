package daemon

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/xzcode/network-ex/internal/control/managed"
	"github.com/xzcode/network-ex/internal/dataplane/tunnel"
	"github.com/xzcode/network-ex/internal/platform/ipc"
	"github.com/xzcode/network-ex/internal/platform/localfile"
)

const MaxRequest = 64 * 1024
const MaxResponse = 256 * 1024

type Request struct {
	Action  string `json:"action"`
	Slot    int    `json:"slot,omitempty"`
	Server  string `json:"server,omitempty"`
	Name    string `json:"name,omitempty"`
	Invite  string `json:"invite,omitempty"`
	CAPEM   string `json:"ca_pem,omitempty"`
	Confirm bool   `json:"confirm,omitempty"`
}
type Status struct {
	Platform      string               `json:"platform"`
	Version       string               `json:"version"`
	Profile       *managed.State       `json:"profile,omitempty"`
	ProfileExists bool                 `json:"profile_exists"`
	Running       bool                 `json:"running"`
	Desired       bool                 `json:"desired"`
	Managed       *managed.LocalStatus `json:"managed,omitempty"`
	Tunnel        *tunnel.Status       `json:"tunnel,omitempty"`
	Error         string               `json:"error,omitempty"`
}
type ProfileSummary struct {
	Slot    int    `json:"slot"`
	Exists  bool   `json:"exists"`
	Name    string `json:"name,omitempty"`
	IP      string `json:"ip,omitempty"`
	Server  string `json:"server,omitempty"`
	Running bool   `json:"running"`
	Desired bool   `json:"desired"`
	State   string `json:"state,omitempty"`
}
type Response struct {
	Profiles []ProfileSummary `json:"profiles,omitempty"`
	OK       bool             `json:"ok"`
	Error    string           `json:"error,omitempty"`
	Status   *Status          `json:"status,omitempty"`
}
type Options struct {
	ExitVia                       string
	ExitTargets, AllowExitTargets []string
	Profiles                      int
	DNSHub                        *managed.DNSHub
	DNSProfile                    string
	DNSListen                     string
	AllowSubnets                  []string
	Root, Socket, Interface       string
	SocketGID                     int
	Port                          uint16
	ICEInterfaces                 []string
}
type prefs struct {
	Desired bool `json:"desired"`
}
type Daemon struct {
	ctx     context.Context
	opt     Options
	mu      sync.Mutex
	desired bool
	stop    context.CancelFunc
	done    chan error
	lastErr string
}

func DefaultRoot() string {
	switch runtime.GOOS {
	case "darwin":
		return "/Library/Application Support/Network EX"
	case "windows":
		return filepath.Join(os.Getenv("ProgramData"), "Network EX")
	default:
		return "/var/lib/network-ex"
	}
}
func DefaultInterface() string {
	if runtime.GOOS == "darwin" {
		return "utun"
	}
	return "nex0"
}
func writePrivateJSON(path string, v any) error {
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".network-ex-")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if e = localfile.Check(f.Name(), false, 0); e != nil {
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
func readPrivateJSON(path string, v any, max int64) error {
	if e := localfile.Check(path, false, max); e != nil {
		return e
	}
	b, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	return json.Unmarshal(b, v)
}
func (d *Daemon) profile() string { return filepath.Join(d.opt.Root, "device") }
func (d *Daemon) saveDesired(v bool) error {
	if e := writePrivateJSON(filepath.Join(d.opt.Root, "settings.json"), prefs{v}); e != nil {
		return e
	}
	d.desired = v
	return nil
}
func (d *Daemon) reap() {
	if d.done != nil {
		select {
		case e := <-d.done:
			d.done = nil
			d.stop = nil
			if e != nil {
				d.lastErr = e.Error()
			}
		default:
		}
	}
}
func (d *Daemon) start() error {
	d.reap()
	if d.done != nil {
		return nil
	}
	if _, e := managed.Load(d.profile()); e != nil {
		return fmt.Errorf("profile not enrolled: %w", e)
	}
	if e := d.saveDesired(true); e != nil {
		return e
	}
	ctx, cancel := context.WithCancel(d.ctx)
	d.stop = cancel
	d.done = make(chan error, 1)
	done := d.done
	d.lastErr = ""
	go func() {
		done <- managed.Run(ctx, managed.Options{ExitVia: d.opt.ExitVia, ExitTargets: d.opt.ExitTargets, AllowExitTargets: d.opt.AllowExitTargets, DNSListen: d.opt.DNSListen, DNSHub: d.opt.DNSHub, DNSProfile: d.opt.DNSProfile, AllowSubnets: d.opt.AllowSubnets, Dir: d.profile(), Interface: d.opt.Interface, Port: d.opt.Port, ICEInterfaces: d.opt.ICEInterfaces})
	}()
	return nil
}
func (d *Daemon) stopRun(persist bool) error {
	if persist {
		if e := d.saveDesired(false); e != nil {
			return e
		}
	}
	d.reap()
	if d.done == nil {
		return nil
	}
	d.stop()
	select {
	case e := <-d.done:
		d.done = nil
		d.stop = nil
		if e != nil {
			d.lastErr = e.Error()
		}
		return nil
	case <-time.After(20 * time.Second):
		return errors.New("agent still stopping")
	}
}
func (d *Daemon) status() Status {
	d.reap()
	s := Status{Platform: runtime.GOOS, Version: "0.6.1-dev-m6", Running: d.done != nil, Desired: d.desired, Error: d.lastErr}
	if _, e := os.Lstat(d.profile()); e == nil {
		s.ProfileExists = true
	}
	if v, e := managed.Load(d.profile()); e == nil {
		// Do not expose private keys or local CA path to the UI.
		v.CA = ""
		s.Profile = &v
		var m managed.LocalStatus
		if readPrivateJSON(filepath.Join(d.profile(), "managed.json"), &m, MaxResponse) == nil {
			s.Managed = &m
		}
		var t tunnel.Status
		if s.Running && readPrivateJSON(filepath.Join(d.profile(), "tunnel.json"), &t, MaxResponse) == nil && time.Since(t.UpdatedAt) < 10*time.Second {
			s.Tunnel = &t
		}
	}
	return s
}
func (d *Daemon) enroll(r Request) error {
	if d.done != nil {
		return errors.New("disconnect before enrollment")
	}
	if _, e := os.Lstat(d.profile()); e == nil {
		return errors.New("profile already exists; forget it explicitly before enrollment")
	} else if !os.IsNotExist(e) {
		return e
	}
	if len(r.Invite) != 43 || len(r.Name) < 1 || len(r.Name) > 80 || len(r.CAPEM) > 32*1024 {
		return errors.New("invalid enrollment fields")
	}
	ca := ""
	if r.CAPEM != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(r.CAPEM)) {
			return errors.New("invalid private CA certificate")
		}
		ca = filepath.Join(d.opt.Root, "enrollment-ca.pem")
		f, e := os.OpenFile(ca, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return e
		}
		if e = localfile.Check(ca, false, 0); e != nil {
			f.Close()
			return e
		}
		_, e = f.WriteString(r.CAPEM)
		f.Close()
		if e != nil {
			return e
		}
	}
	f, e := os.CreateTemp(d.opt.Root, "invite-")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if e = localfile.Check(f.Name(), false, 0); e != nil {
		f.Close()
		return e
	}
	_, e = f.WriteString(r.Invite)
	f.Close()
	if e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(d.ctx, 10*time.Second)
	defer cancel()
	if _, e = managed.Enroll(ctx, r.Server, ca, f.Name(), r.Name, d.profile()); e != nil {
		return e
	}
	return d.saveDesired(false)
}
func (d *Daemon) handle(r Request) Response {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.reap()
	var e error
	switch r.Action {
	case "status", "diagnostics":
	case "enroll":
		e = d.enroll(r)
	case "connect":
		e = d.start()
	case "disconnect":
		e = d.stopRun(true)
	case "forget":
		if !r.Confirm {
			e = errors.New("explicit confirmation required")
			break
		}
		if d.done != nil {
			e = errors.New("disconnect before forgetting profile")
			break
		}
		if e = d.saveDesired(false); e != nil {
			break
		}
		// Fixed service-owned paths, no user-supplied filesystem paths.
		e = os.RemoveAll(d.profile())
		if e == nil {
			ca := filepath.Join(d.opt.Root, "enrollment-ca.pem")
			if x := os.Remove(ca); x != nil && !os.IsNotExist(x) {
				e = x
			}
		}
		if e == nil {
			d.lastErr = ""
		}
	default:
		e = errors.New("unknown IPC action")
	}
	s := d.status()
	res := Response{OK: e == nil, Status: &s}
	if e != nil {
		res.Error = e.Error()
	}
	return res
}
func Serve(ctx context.Context, opt Options) error {
	if opt.Root == "" || opt.Socket == "" || opt.Interface == "" || opt.Port == 0 {
		return errors.New("invalid daemon configuration")
	}
	root, e := filepath.Abs(opt.Root)
	if e != nil {
		return e
	}
	opt.Root = root
	if e = localfile.Check(root, true, 0); e != nil {
		return fmt.Errorf("prepare private service state directory: %w", e)
	}
	if e = localfile.CheckOwner(root); e != nil {
		return e
	}
	l, e := ipc.Listen(opt.Socket, opt.SocketGID)
	if e != nil {
		return e
	}
	defer l.Close()
	sup, e := newSupervisor(ctx, opt)
	if e != nil {
		return e
	}
	defer sup.shutdown()
	closeListener := context.AfterFunc(ctx, func() { l.Close() })
	defer closeListener()
	var wg sync.WaitGroup
	slots := make(chan struct{}, 16)
	defer wg.Wait()
	for {
		c, e := l.Accept()
		if e != nil {
			if ctx.Err() != nil {
				return nil
			}
			return e
		}
		select {
		case slots <- struct{}{}:
		default:
			c.Close()
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-slots }()
			defer c.Close()
			stop := context.AfterFunc(ctx, func() { c.Close() })
			defer stop()
			_ = c.SetDeadline(time.Now().Add(30 * time.Second))
			var r Request
			dec := json.NewDecoder(io.LimitReader(c, MaxRequest))
			dec.DisallowUnknownFields()
			if e := dec.Decode(&r); e != nil {
				_ = json.NewEncoder(c).Encode(Response{Error: "invalid IPC request"})
				return
			}
			if ctx.Err() != nil {
				return
			}
			_ = json.NewEncoder(c).Encode(sup.handle(r))
		}()
	}
}
func Call(ctx context.Context, address string, r Request) (Response, error) {
	var out Response
	c, e := ipc.Dial(ctx, address)
	if e != nil {
		return out, e
	}
	defer c.Close()
	deadline := time.Now().Add(30 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	c.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	if e = json.NewEncoder(c).Encode(r); e != nil {
		return out, e
	}
	e = json.NewDecoder(io.LimitReader(c, MaxResponse)).Decode(&out)
	return out, e
}
func ReadRequest(r io.Reader) (Request, error) {
	var v Request
	d := json.NewDecoder(io.LimitReader(r, MaxRequest))
	d.DisallowUnknownFields()
	e := d.Decode(&v)
	if e == nil && strings.TrimSpace(v.Action) == "" {
		e = errors.New("action required")
	}
	return v, e
}
