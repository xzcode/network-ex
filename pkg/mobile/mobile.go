// Package mobile exposes the narrowly scoped native VPN integration.
// It deliberately has no root operations, shell commands, or unprotected
// direct ICE sockets in its initial Android transport.
package mobile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/xzcode/network-ex/internal/control/managed"
	"github.com/xzcode/network-ex/internal/dataplane/tunnel"
	"github.com/xzcode/network-ex/internal/platform/localfile"
	"github.com/xzcode/network-ex/internal/platform/packetfd"
	"github.com/xzcode/network-ex/internal/platform/protect"
	wgtun "golang.zx2c4.com/wireguard/tun"
)

// Platform is implemented by Android VpnService. OpenTunnel receives a
// validated JSON split-route specification and transfers a detached fd.
// ProtectSocket must return false if VpnService.protect fails.
type Platform interface {
	OpenTunnel(spec string) int32
	ProtectSocket(fd int32) bool
}
type tunnelSpec struct {
	Address string   `json:"address"`
	MTU     int      `json:"mtu"`
	Routes  []string `json:"routes"`
}
type Session struct {
	mu       sync.Mutex
	platform Platform
	dir      string
	cancel   context.CancelFunc
	done     chan struct{}
	err      string
}

func Version() string                { return "0.8.0-dev-m8" }
func NewSession(p Platform) *Session { return &Session{platform: p} }
func checkedRoot(root string) (string, error) {
	p, e := filepath.Abs(root)
	if e != nil {
		return "", e
	}
	if e = localfile.Check(p, true, 0); e != nil {
		return "", e
	}
	return p, nil
}

// Enrollment is synchronous and must be called from a native worker, never UI.
// App-private root is created by the OS. Identity and WireGuard keys stay local.
func Enroll(root, server, name, invite, caPEM string) (string, error) {
	root, e := checkedRoot(root)
	if e != nil {
		return "", e
	}
	if len(invite) != 43 || len(caPEM) > 32768 {
		return "", errors.New("invalid invitation or CA size")
	}
	unlock, e := lockRoot(root)
	if e != nil {
		return "", e
	}
	defer unlock()
	dir := filepath.Join(root, "device")
	if _, e = os.Lstat(dir); !os.IsNotExist(e) {
		return "", errors.New("existing device profile; explicitly forget it before enrolling")
	}
	f, e := os.CreateTemp(root, "invite-")
	if e != nil {
		return "", e
	}
	defer os.Remove(f.Name())
	if _, e = f.WriteString(invite); e != nil {
		f.Close()
		return "", e
	}
	if e = f.Close(); e != nil {
		return "", e
	}
	ca := ""
	if caPEM != "" {
		ca = filepath.Join(root, "private-ca.pem")
		f, e := os.OpenFile(ca, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return "", e
		}
		if _, e = f.WriteString(caPEM); e != nil {
			f.Close()
			return "", e
		}
		if e = f.Close(); e != nil {
			return "", e
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	d, e := managed.Enroll(ctx, server, ca, filepath.Join(root, filepath.Base(f.Name())), name, dir)
	if e != nil {
		return "", e
	}
	b, e := json.Marshal(d)
	return string(b), e
}
func HasProfile(root string) bool {
	root, e := checkedRoot(root)
	if e != nil {
		return false
	}
	_, e = managed.Load(filepath.Join(root, "device"))
	return e == nil
}
func (s *Session) Start(root string) error {
	root, e := checkedRoot(root)
	if e != nil {
		return e
	}
	if s.platform == nil {
		return errors.New("VPN platform required")
	}
	unlock, e := lockRoot(root)
	if e != nil {
		return e
	}
	transferred := false
	defer func() {
		if !transferred {
			unlock()
		}
	}()
	dir := filepath.Join(root, "device")
	if _, e = managed.Load(dir); e != nil {
		return e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done != nil {
		return errors.New("session already running")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	_ = os.Remove(filepath.Join(dir, "tunnel.json"))
	s.dir = dir
	s.cancel = cancel
	s.done = done
	s.err = ""
	// Native OpenTunnel may call into platform APIs; never hold session mutex
	// while invoking it or when waiting for a session to finish.
	ext := &tunnel.External{
		Protect: protect.Protector(func(fd int) bool { return s.platform.ProtectSocket(int32(fd)) }),
		Open: func(ctx context.Context, ip netip.Addr, routes []netip.Prefix) (wgtun.Device, error) {
			spec := tunnelSpec{Address: ip.String(), MTU: 1280, Routes: []string{}}
			for _, r := range routes {
				spec.Routes = append(spec.Routes, r.String())
			}
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			b, e := json.Marshal(spec)
			if e != nil {
				return nil, e
			}
			fd := s.platform.OpenTunnel(string(b))
			d, e := packetfd.New(int(fd), "mobile0")
			if e != nil {
				return nil, e
			}
			if ctx.Err() != nil {
				d.Close()
				return nil, ctx.Err()
			}
			return d, nil
		},
	}
	transferred = true
	go func() {
		err := managed.Run(ctx, managed.Options{Dir: dir, Interface: "mobile0", Port: 51820, External: ext})
		s.mu.Lock()
		defer s.mu.Unlock()
		if err != nil && ctx.Err() == nil {
			s.err = err.Error()
		}
		unlock()
		s.cancel = nil
		s.done = nil
		close(done)
	}()
	return nil
}
func (s *Session) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil {
		s.cancel()
	}
}
func (s *Session) WaitStopped(timeoutMillis int32) bool {
	s.mu.Lock()
	d := s.done
	s.mu.Unlock()
	if d == nil {
		return true
	}
	if timeoutMillis < 0 || timeoutMillis > 30000 {
		return false
	}
	select {
	case <-d:
		return true
	case <-time.After(time.Duration(timeoutMillis) * time.Millisecond):
		return false
	}
}

type status struct {
	Running bool                 `json:"running"`
	Error   string               `json:"error,omitempty"`
	Managed *managed.LocalStatus `json:"managed,omitempty"`
	Tunnel  *tunnel.Status       `json:"tunnel,omitempty"`
}

func (s *Session) Status() string {
	s.mu.Lock()
	dir, running, err := s.dir, s.done != nil, s.err
	s.mu.Unlock()
	v := status{Running: running, Error: err}
	if dir != "" {
		var m managed.LocalStatus
		if readStatus(filepath.Join(dir, "managed.json"), &m) == nil {
			v.Managed = &m
		}
		var t tunnel.Status
		if running && readStatus(filepath.Join(dir, "tunnel.json"), &t) == nil && time.Since(t.UpdatedAt) < 5*time.Second && t.State == "running" {
			v.Tunnel = &t
		}
	}
	b, _ := json.Marshal(v)
	return string(b)
}
func readStatus(p string, v any) error {
	if e := localfile.Check(p, false, 256*1024); e != nil {
		return e
	}
	b, e := os.ReadFile(p)
	if e != nil {
		return e
	}
	return json.Unmarshal(b, v)
}

// Forget is a local operation only; call after the service has fully stopped.
// Fixed app-private paths, not a general file deletion API.
func Forget(root string) error {
	root, e := checkedRoot(root)
	if e != nil {
		return e
	}
	unlock, e := lockRoot(root)
	if e != nil {
		return e
	}
	defer unlock()
	dir := filepath.Join(root, "device")
	if _, e = os.Lstat(filepath.Join(dir, "run.lock")); e == nil {
		return errors.New("stop session before forgetting profile")
	} else if !os.IsNotExist(e) {
		return e
	}
	if e = os.RemoveAll(dir); e != nil {
		return e
	}
	if e = os.Remove(filepath.Join(root, "private-ca.pem")); e != nil && !os.IsNotExist(e) {
		return fmt.Errorf("remove CA: %w", e)
	}
	return nil
}
