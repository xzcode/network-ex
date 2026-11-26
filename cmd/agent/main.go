package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/xzcode/network-ex/internal/control/managed"
	"github.com/xzcode/network-ex/internal/dataplane/relay"
	"github.com/xzcode/network-ex/internal/dataplane/tunnel"
	"golang.org/x/crypto/curve25519"
)

const version = "0.3.0-dev-m3"

func main() {
	if e := run(os.Args[1:]); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: agent version | keygen | check | run | status | managed-enroll | managed-run")
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
		iface := f.String("interface", "nex0", "TUN interface name")
		port := f.Uint("listen-port", 51820, "UDP port")
		iceIf := f.String("ice-interfaces", "", "comma-separated interface allowlist")
		relayCA := f.String("relay-ca", "", "optional separate relay CA")
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
		return managed.Run(ctx, managed.Options{Dir: *dir, Interface: *iface, Port: uint16(*port), ICEInterfaces: ifaces, RelayCA: *relayCA})
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
