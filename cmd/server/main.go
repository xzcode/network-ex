package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/xzcode/network-ex/internal/dataplane/relay"
)

const version = "0.1.0-dev-m1"

func main() {
	if e := run(os.Args[1:]); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run(args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "version":
			fmt.Println(version)
			return nil
		case "issuer-keygen":
			f := flag.NewFlagSet("issuer-keygen", flag.ContinueOnError)
			out := f.String("out", "", "private key path")
			if e := f.Parse(args[1:]); e != nil {
				return e
			}
			if *out == "" {
				return errors.New("-out required")
			}
			pub, k, e := ed25519.GenerateKey(rand.Reader)
			if e != nil {
				return e
			}
			if e = relay.WriteSecret(*out, k); e != nil {
				return e
			}
			fmt.Printf("%x\n", pub)
			return nil
		case "lease":
			f := flag.NewFlagSet("lease", flag.ContinueOnError)
			key := f.String("issuer-key", "", "private key file")
			node := f.String("node", "", "node ID")
			network := f.String("network", "", "network ID")
			flow := f.String("flow", "", "flow ID")
			a := f.String("a", "", "device A identity public hex")
			b := f.String("b", "", "device B identity public hex")
			ttl := f.Duration("ttl", 10*time.Minute, "max 15m")
			out := f.String("out", "", "new token file")
			if e := f.Parse(args[1:]); e != nil {
				return e
			}
			if *out == "" || *ttl <= 0 || *ttl > 15*time.Minute {
				return errors.New("-out and valid ttl required")
			}
			k, e := relay.ReadHex(*key, ed25519.PrivateKeySize, true)
			if e != nil {
				return e
			}
			v, e := relay.Issue(k, relay.Lease{Node: *node, Network: *network, Flow: *flow, A: *a, B: *b, Expires: time.Now().Add(*ttl).Unix()})
			if e != nil {
				return e
			}
			file, e := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if e != nil {
				return e
			}
			defer file.Close()
			_, e = file.WriteString(v + "\n")
			return e
		}
	}
	f := flag.NewFlagSet("server", flag.ContinueOnError)
	mode := f.String("mode", "relay", "M1 supports relay only")
	listen := f.String("listen", "127.0.0.1:8443", "TLS listener")
	node := f.String("node", "", "node ID")
	issuer := f.String("issuer-public", "", "issuer public hex file")
	cert := f.String("tls-cert", "", "TLS cert")
	key := f.String("tls-key", "", "TLS key")
	if e := f.Parse(args); e != nil {
		return e
	}
	if *mode != "relay" {
		return errors.New("M1 implements relay only; management/all planned M3")
	}
	if *node == "" || *issuer == "" || *cert == "" || *key == "" {
		return errors.New("node, issuer-public, tls-cert and tls-key required")
	}
	p, e := relay.ReadHex(*issuer, ed25519.PublicKeySize, false)
	if e != nil {
		return e
	}
	srv := &http.Server{Addr: *listen, Handler: relay.NewServer(*node, p), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 * 1024, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(c)
	}()
	e = srv.ListenAndServeTLS(*cert, *key)
	if errors.Is(e, http.ErrServerClosed) {
		return nil
	}
	return e
}

var _ = hex.EncodeToString
