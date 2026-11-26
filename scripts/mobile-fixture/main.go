//go:build linux && !android

// Test-only Linux native VPN adapter. Never include this in Android packages.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/xzcode/network-ex/pkg/mobile"
	"golang.org/x/sys/unix"
)

type fixture struct {
	allow             bool
	protected, opened atomic.Uint64
}

func (f *fixture) ProtectSocket(fd int32) bool { f.protected.Add(1); return f.allow && fd >= 0 }
func ip(args ...string) error {
	b, e := exec.Command("ip", args...).CombinedOutput()
	if e != nil {
		return fmt.Errorf("%w: %s", e, b)
	}
	return nil
}
func (f *fixture) OpenTunnel(raw string) int32 {
	var s struct {
		Address string
		MTU     int
		Routes  []string
	}
	if json.Unmarshal([]byte(raw), &s) != nil || s.MTU != 1280 {
		return -1
	}
	addr, e := netip.ParseAddr(s.Address)
	if e != nil || !addr.Is4() || !addr.IsPrivate() {
		return -1
	}
	ifr, e := unix.NewIfreq("nxmobile0")
	if e != nil {
		return -1
	}
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_TUN_EXCL)
	fd, e := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if e != nil {
		return -1
	}
	fail := func(e error) int32 { fmt.Fprintln(os.Stderr, e); unix.Close(fd); return -1 }
	if e = unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); e != nil {
		return fail(e)
	}
	name := ifr.Name()
	if e = ip("link", "set", "dev", name, "mtu", "1280", "up"); e != nil {
		return fail(e)
	}
	if e = ip("-4", "addr", "add", s.Address+"/32", "dev", name); e != nil {
		return fail(e)
	}
	for _, r := range s.Routes {
		p, e := netip.ParsePrefix(r)
		if e != nil || p.Bits() != 32 || !p.Addr().IsPrivate() {
			return fail(errors.New("unexpected native VPN route"))
		}
		if e = ip("-4", "route", "add", r, "dev", name); e != nil {
			return fail(e)
		}
	}
	f.opened.Add(1)
	return int32(fd)
}
func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) < 2 {
		return errors.New("enroll or run")
	}
	f := flag.NewFlagSet(os.Args[1], flag.ContinueOnError)
	root := f.String("root", "", "private state root")
	server := f.String("server", "", "HTTPS")
	name := f.String("name", "", "device")
	invite := f.String("invite-file", "", "test invite file")
	ca := f.String("ca", "", "test CA")
	deny := f.Bool("deny-protect", false, "negative test")
	direct := f.Bool("direct", false, "enable protected ICE")
	if e := f.Parse(os.Args[2:]); e != nil {
		return e
	}
	switch os.Args[1] {
	case "enroll":
		i, e := os.ReadFile(*invite)
		if e != nil {
			return e
		}
		b, e := os.ReadFile(*ca)
		if e != nil {
			return e
		}
		// Script creates invitation files with a single trailing newline.
		if len(i) > 0 && i[len(i)-1] == '\n' {
			i = i[:len(i)-1]
		}
		d, e := mobile.Enroll(*root, *server, *name, string(i), string(b))
		if e != nil {
			return e
		}
		fmt.Println(d)
		return nil
	case "run":
		p := &fixture{allow: !*deny}
		s := mobile.NewSession(p)
		if e := s.StartWithDirect(*root, *direct); e != nil {
			return e
		}
		ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
		defer cancel()
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				s.Stop()
				if !s.WaitStopped(15000) {
					return errors.New("native VPN did not stop")
				}
				fmt.Printf("protected=%d opened=%d\n", p.protected.Load(), p.opened.Load())
				return nil
			case <-tick.C:
				if s.WaitStopped(0) {
					fmt.Println(s.Status())
					fmt.Printf("protected=%d opened=%d\n", p.protected.Load(), p.opened.Load())
					return errors.New("session stopped")
				}
			}
		}
	default:
		return errors.New("unknown test command")
	}
}
