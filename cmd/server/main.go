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
	"github.com/xzcode/network-ex/internal/node/registration"
	"github.com/xzcode/network-ex/internal/platform/localfile"
	"github.com/xzcode/network-ex/pkg/protocol"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/xzcode/network-ex/internal/control"
	"github.com/xzcode/network-ex/internal/dataplane/relay"
	stunserver "github.com/xzcode/network-ex/internal/node/stun"
)

const version = "0.5.0-dev-m5"

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
		case "admin-bootstrap":
			f := flag.NewFlagSet("admin-bootstrap", flag.ContinueOnError)
			db := f.String("db", "", "SQLite path")
			username := f.String("username", "", "administrator login")
			password := f.String("password-file", "", "0600 password file")
			if e := f.Parse(args[1:]); e != nil {
				return e
			}
			pw, e := control.PasswordFile(*password)
			if e != nil {
				return e
			}
			store, e := control.Open(*db)
			if e != nil {
				return e
			}
			defer store.Close()
			if e = store.Bootstrap(*username, pw); e != nil {
				return e
			}
			fmt.Println("administrator initialized")
			return nil
		case "issuer-keygen", "node-keygen":
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
	mode := f.String("mode", "relay", "all, management or relay")
	db := f.String("db", "", "SQLite database path for management/all")
	signingKey := f.String("issuer-key", "", "issuer private key file for management/all")
	relayURL := f.String("relay-url", "", "advertised wss relay URL")
	stunURL := f.String("stun-url", "", "advertised STUN URL")
	stunListen := f.String("stun-listen", "", "optional IPv4 UDP STUN listener")
	listen := f.String("listen", "127.0.0.1:8443", "TLS listener")
	node := f.String("node", "", "node ID")
	issuer := f.String("issuer-public", "", "issuer public hex file")
	cert := f.String("tls-cert", "", "TLS cert")
	key := f.String("tls-key", "", "TLS key")
	mgmtURL := f.String("management-url", "", "HTTPS management origin for a registered relay")
	mgmtCA := f.String("management-ca", "", "management CA PEM")
	nodeKey := f.String("node-key", "", "relay node identity private key")
	nodeInvite := f.String("node-invite-file", "", "0600 one-time node invitation file")

	if e := f.Parse(args); e != nil {
		return e
	}
	if *mode != "all" && *mode != "management" && *mode != "relay" {
		return errors.New("mode must be all, management or relay")
	}
	if *node == "" || *cert == "" || *key == "" {
		return errors.New("node, tls-cert and tls-key required")
	}
	if *mode == "management" && *stunListen != "" {
		return errors.New("management-only mode cannot listen for STUN")
	}
	if *mode == "all" && *relayURL == "" {
		return errors.New("all mode requires advertised relay URL")
	}
	if *mode != "relay" && (*mgmtURL != "" || *nodeKey != "" || *nodeInvite != "" || *mgmtCA != "") {
		return errors.New("node registration flags require relay mode")
	}
	if *mgmtURL == "" && (*nodeKey != "" || *nodeInvite != "" || *mgmtCA != "") {
		return errors.New("management-url required for registered relay")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var pub ed25519.PublicKey
	var management *control.Service
	mux := http.NewServeMux()
	if *mode != "relay" {
		k, e := relay.ReadHex(*signingKey, ed25519.PrivateKeySize, true)
		if e != nil {
			return e
		}
		priv := ed25519.PrivateKey(k)
		pub = priv.Public().(ed25519.PublicKey)
		store, e := control.Open(*db)
		if e != nil {
			return e
		}
		defer store.Close()
		management, e = control.NewService(store, priv, *node, *relayURL, *stunURL)
		if e != nil {
			return e
		}
		mux.Handle("/", management.Handler())
	} else {
		p, e := relay.ReadHex(*issuer, ed25519.PublicKeySize, false)
		if e != nil {
			return e
		}
		pub = p
	}
	if *mode != "management" {
		rs, ss := relay.NewServer(*node, pub), relay.NewSignalServer(*node, pub)
		if *mgmtURL != "" {
			k, e := relay.ReadHex(*nodeKey, ed25519.PrivateKeySize, true)
			if e != nil {
				return e
			}
			client, e := registration.New(ctx, *node, *mgmtURL, *mgmtCA, ed25519.PrivateKey(k))
			if e != nil {
				return e
			}
			reply, e := client.Heartbeat(protocol.NodeStats{})
			if e != nil && *nodeInvite != "" {
				if e = localfile.Check(*nodeInvite, false, 512); e != nil {
					return e
				}
				b, e := os.ReadFile(*nodeInvite)
				if e != nil {
					return e
				}
				if _, e = client.Enroll(strings.TrimSpace(string(b))); e != nil {
					return e
				}
				reply, e = client.Heartbeat(protocol.NodeStats{})
			}
			if e != nil {
				return e
			}
			rs.SetLimits(reply.Limits)
			rs.Authorize = client.Authorize
			ss.Authorize = client.Authorize
			go client.Run(rs)
		}
		if management != nil {
			rs.Authorize = management.AuthorizeLease
			ss.Authorize = management.AuthorizeLease
		}
		mux.Handle("/relay/v1", rs)
		mux.Handle("/signal/v1", ss)
		if *mode == "relay" {
			mux.Handle("/", rs)
		}
	}
	srv := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 * 1024, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	if *stunListen != "" {
		addr, e := net.ResolveUDPAddr("udp4", *stunListen)
		if e != nil {
			return e
		}
		sock, e := net.ListenUDP("udp4", addr)
		if e != nil {
			return e
		}
		defer sock.Close()
		go func() {
			if e := stunserver.Serve(ctx, sock); e != nil {
				fmt.Fprintln(os.Stderr, "STUN listener failed:", e)
				stop()
			}
		}()
	}
	go func() {
		<-ctx.Done()
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(c)
	}()
	e := srv.ListenAndServeTLS(*cert, *key)
	if errors.Is(e, http.ErrServerClosed) {
		return nil
	}
	return e
}

var _ = hex.EncodeToString
