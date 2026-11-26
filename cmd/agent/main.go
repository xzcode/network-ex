package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/xzcode/network-ex/internal/control/daemon"
	"github.com/xzcode/network-ex/internal/control/managed"
	"github.com/xzcode/network-ex/internal/dataplane/relay"
	"github.com/xzcode/network-ex/internal/dataplane/tunnel"
	"github.com/xzcode/network-ex/internal/platform/ipc"
	"github.com/xzcode/network-ex/internal/platform/service"
	"golang.org/x/crypto/curve25519"
)

const version = "0.6.1-dev-m6"

func main() {
	if e := run(os.Args[1:]); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: agent version | keygen | check | run | status | managed-enroll | managed-run | daemon | ctl")
	}
	switch args[0] {
	case "version":
		fmt.Println(version)
		return nil
	case "keygen":
		f := flag.NewFlagSet("keygen", flag.ContinueOnError)
		kind := f.String("kind", "wg", "wg or identity")
		out := f.String("out", "", "private key path (new file)")
		if e := f.Parse(args[1:]); e != nil {
			return e
		}
		if *out == "" {
			return errors.New("-out required")
		}
		if *kind == "identity" {
			pub, k, e := ed25519.GenerateKey(rand.Reader)
			if e != nil {
				return e
			}
			if e = relay.WriteSecret(*out, k); e != nil {
				return e
			}
			fmt.Printf("%x\n", pub)
			return nil
		}
		if *kind != "wg" {
			return errors.New("unknown key kind")
		}
		k := make([]byte, 32)
		if _, e := rand.Read(k); e != nil {
			return e
		}
		k[0] &= 248
		k[31] &= 127
		k[31] |= 64
		pub, e := curve25519.X25519(k, curve25519.Basepoint)
		if e != nil {
			return e
		}
		if e = relay.WriteSecret(*out, k); e != nil {
			return e
		}
		fmt.Printf("%x\n", pub)
		return nil
	case "daemon":
		f := flag.NewFlagSet("daemon", flag.ContinueOnError)
		root := f.String("state-root", daemon.DefaultRoot(), "prepared private service root")
		profiles := f.Int("profiles", 8, "maximum local network profiles (1-8)")
		exitVia := f.String("exit-via", "", "default profile approved exit gateway device ID")
		exitTargets := f.String("exit-targets", "", "default profile selected public IPv4 targets")
		allowExit := f.String("allow-exit-targets", "", "default profile gateway target opt-in")
		sock := f.String("socket", ipc.DefaultAddress(), "local IPC address")
		gid := f.Int("socket-gid", -1, "Unix socket group id; default process group")
		iface := f.String("interface", daemon.DefaultInterface(), "overlay interface")
		port := f.Uint("listen-port", 51820, "UDP port")
		iceIf := f.String("ice-interfaces", "", "comma-separated ICE interface allowlist")
		allowSubnets := f.String("allow-subnets", "", "comma-separated approved private CIDRs, local gateway opt-in")
		dnsListen := f.String("dns-listen", "", "optional loopback DNS listener (e.g. 127.0.0.1:15353)")
		if e := f.Parse(args[1:]); e != nil {
			return e
		}
		if *port == 0 || *port > 65535 {
			return errors.New("invalid listen-port")
		}
		var ifaces []string
		for _, v := range strings.Split(*iceIf, ",") {
			if v = strings.TrimSpace(v); v != "" {
				ifaces = append(ifaces, v)
			}
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return service.Run(ctx, func(c context.Context) error {
			return daemon.Serve(c, daemon.Options{ExitVia: *exitVia, ExitTargets: splitList(*exitTargets), AllowExitTargets: splitList(*allowExit), Profiles: *profiles, DNSListen: *dnsListen, AllowSubnets: splitList(*allowSubnets), Root: *root, Socket: *sock, SocketGID: *gid, Interface: *iface, Port: uint16(*port), ICEInterfaces: ifaces})
		})
	case "ctl":
		f := flag.NewFlagSet("ctl", flag.ContinueOnError)
		sock := f.String("socket", ipc.DefaultAddress(), "local IPC address")
		if e := f.Parse(args[1:]); e != nil {
			return e
		}
		req, e := daemon.ReadRequest(os.Stdin)
		if e != nil {
			return e
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		res, e := daemon.Call(ctx, *sock, req)
		if e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(res)
	case "managed-enroll":
		f := flag.NewFlagSet("managed-enroll", flag.ContinueOnError)
		server := f.String("server", "", "management HTTPS origin")
		ca := f.String("ca", "", "optional CA PEM")
		invite := f.String("invite-file", "", "0600 invite file")
		name := f.String("name", "", "device name")
		dir := f.String("state-dir", "", "new 0700 state directory")
		if e := f.Parse(args[1:]); e != nil {
			return e
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		d, e := managed.Enroll(ctx, *server, *ca, *invite, *name, *dir)
		if e != nil {
			return e
		}
		fmt.Printf("device %s enrolled, awaiting approval\n", d.ID)
		return nil
	case "managed-run":
		f := flag.NewFlagSet("managed-run", flag.ContinueOnError)
		dir := f.String("state-dir", "", "enrolled state directory")
		iface := f.String("interface", daemon.DefaultInterface(), "TUN interface name")
		port := f.Uint("listen-port", 51820, "UDP port")
		iceIf := f.String("ice-interfaces", "", "comma-separated interface allowlist")
		relayCA := f.String("relay-ca", "", "optional separate relay CA")
		exitVia := f.String("exit-via", "", "approved exit gateway device ID")
		exitTargets := f.String("exit-targets", "", "comma-separated selected public IPv4 targets")
		allowExit := f.String("allow-exit-targets", "", "comma-separated public IPv4 targets this gateway may forward")
		allowSubnets := f.String("allow-subnets", "", "comma-separated approved private CIDRs, local gateway opt-in")
		dnsListen := f.String("dns-listen", "", "optional loopback DNS listener (e.g. 127.0.0.1:15353)")
		if e := f.Parse(args[1:]); e != nil {
			return e
		}
		if *dir == "" || *port == 0 || *port > 65535 {
			return errors.New("state-dir and valid listen-port required")
		}
		var ifaces []string
		for _, v := range strings.Split(*iceIf, ",") {
			if v = strings.TrimSpace(v); v != "" {
				ifaces = append(ifaces, v)
			}
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return managed.Run(ctx, managed.Options{ExitVia: *exitVia, ExitTargets: splitList(*exitTargets), AllowExitTargets: splitList(*allowExit), DNSListen: *dnsListen, AllowSubnets: splitList(*allowSubnets), Dir: *dir, Interface: *iface, Port: uint16(*port), ICEInterfaces: ifaces, RelayCA: *relayCA})
	case "status":
		f := flag.NewFlagSet("status", flag.ContinueOnError)
		p := f.String("file", "", "status file")
		if e := f.Parse(args[1:]); e != nil {
			return e
		}
		if *p == "" {
			return errors.New("-file required")
		}
		b, e := os.ReadFile(*p)
		if e != nil {
			return e
		}
		fmt.Print(string(b))
		return nil
	case "check", "run":
		f := flag.NewFlagSet(args[0], flag.ContinueOnError)
		p := f.String("config", "", "JSON config")
		if e := f.Parse(args[1:]); e != nil {
			return e
		}
		if *p == "" {
			return errors.New("-config required")
		}
		c, e := tunnel.Load(*p)
		if e != nil {
			return e
		}
		if args[0] == "check" {
			if e = tunnel.Check(c); e != nil {
				return e
			}
			fmt.Println("static config valid (not a connectivity test)")
			return nil
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return tunnel.Run(ctx, c)
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

var _ = hex.EncodeToString

func splitList(raw string) []string {
	var out []string
	for _, v := range strings.Split(raw, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}
