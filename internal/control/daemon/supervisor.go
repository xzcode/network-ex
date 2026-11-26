package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/xzcode/network-ex/internal/control/managed"
	"github.com/xzcode/network-ex/internal/platform/localfile"
)

type supervisor struct {
	slots   []*Daemon
	stopDNS func()
}

func newSupervisor(ctx context.Context, opt Options) (*supervisor, error) {
	count := opt.Profiles
	if count == 0 {
		count = 8
	}
	if count < 1 || count > 8 || int(opt.Port)+count-1 > 65535 {
		return nil, errors.New("profiles must be 1–8 and UDP port range must fit")
	}
	h, stop, e := managed.StartDNSHub(ctx, opt.DNSListen)
	if e != nil {
		return nil, e
	}
	s := &supervisor{stopDNS: stop}
	success := false
	defer func() {
		if !success {
			stop()
		}
	}()
	for i := 0; i < count; i++ {
		o := opt
		o.DNSHub = h
		o.DNSProfile = fmt.Sprintf("p%d", i)
		o.DNSListen = ""
		o.Port = uint16(int(opt.Port) + i)
		if i > 0 {
			// Slot IDs are bounded integers; no user-provided paths or names.
			o.Root = filepath.Join(opt.Root, fmt.Sprintf("profile-%d", i))
			if e = os.Mkdir(o.Root, 0700); e != nil && !os.IsExist(e) {
				return nil, e
			}
			if e = localfile.Check(o.Root, true, 0); e != nil {
				return nil, e
			}
			if e = localfile.CheckOwner(o.Root); e != nil {
				return nil, e
			}
			o.ExitVia = ""
			o.ExitTargets = nil
			o.AllowExitTargets = nil
			o.AllowSubnets = nil // local administrator opt-in belongs only to legacy/default slot
			if runtime.GOOS == "darwin" {
				o.Interface = "utun"
			} else {
				o.Interface = fmt.Sprintf("nex-p%d", i)
			}
			if o.Interface == opt.Interface && runtime.GOOS != "darwin" {
				return nil, errors.New("base interface conflicts with reserved profile interface")
			}
		}
		d := &Daemon{ctx: ctx, opt: o}
		var p prefs
		if e = readPrivateJSON(filepath.Join(o.Root, "settings.json"), &p, 8192); e == nil {
			d.desired = p.Desired
		} else if !os.IsNotExist(e) {
			return nil, e
		}
		s.slots = append(s.slots, d)
	}
	for _, d := range s.slots {
		if d.desired {
			if e = d.start(); e != nil {
				d.lastErr = e.Error()
			}
		}
	}
	success = true
	return s, nil
}
func (s *supervisor) handle(r Request) Response {
	if r.Slot < 0 || r.Slot >= len(s.slots) {
		return Response{Error: "invalid profile slot"}
	}
	d := s.slots[r.Slot]
	if r.Action == "list" {
		out := Response{OK: true}
		for i, v := range s.slots {
			v.mu.Lock()
			st := v.status()
			v.mu.Unlock()
			p := ProfileSummary{Slot: i, Exists: st.ProfileExists, Running: st.Running, Desired: st.Desired}
			if st.Profile != nil {
				p.Server = st.Profile.Server
			}
			if st.Managed != nil {
				p.Name = st.Managed.Device.Name
				p.IP = st.Managed.Device.IP
				p.State = st.Managed.State
			}
			out.Profiles = append(out.Profiles, p)
		}
		return out
	}
	return d.handle(r)
}
func (s *supervisor) shutdown() {
	s.stopDNS()
	var wg sync.WaitGroup
	for _, v := range s.slots {
		wg.Add(1)
		go func(d *Daemon) { defer wg.Done(); d.mu.Lock(); defer d.mu.Unlock(); _ = d.stopRun(false) }(v)
	}
	wg.Wait()
}
