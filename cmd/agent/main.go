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
	"syscall"

	"github.com/xzcode/network-ex/internal/dataplane/relay"
	"github.com/xzcode/network-ex/internal/dataplane/tunnel"
	"golang.org/x/crypto/curve25519"
)

const version = "0.2.0-dev-m2"

func main() {
	if e := run(os.Args[1:]); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: agent version | keygen | check | run | status")
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
