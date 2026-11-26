package managed

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/xzcode/network-ex/pkg/protocol"
	"golang.org/x/net/dns/dnsmessage"
)

const suffix = ".network-ex.internal."

type dnsView struct {
	mu      sync.RWMutex
	records map[string][4]byte
	until   int64
}

func (d *dnsView) Clear() { d.mu.Lock(); defer d.mu.Unlock(); d.records = nil; d.until = 0 }
func (d *dnsView) Update(s protocol.Snapshot) {
	records := map[string][4]byte{}
	add := func(label, raw string) {
		a, e := netip.ParseAddr(raw)
		if e == nil && a.Is4() && protocol.ValidDNSLabel(label) {
			records[label+suffix] = a.As4()
		}
	}
	add(s.DNSLabel, s.Device.IP)
	for _, p := range s.Peers {
		add(p.DNSLabel, p.IP)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.records = records
	d.until = s.ValidUntil
}
func (d *dnsView) lookup(name string) (ip [4]byte, found bool, until int64, ambiguous bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	ip, found = d.records[name]
	return ip, found, d.until, false
}

type lookupFunc func(string) ([4]byte, bool, int64, bool)

func dnsAnswer(b []byte, lookup lookupFunc) ([]byte, error) {
	var q dnsmessage.Message
	if len(b) > 4096 || q.Unpack(b) != nil || q.Header.Response || len(q.Questions) != 1 {
		return nil, errors.New("invalid DNS query")
	}
	question := q.Questions[0]
	name := strings.ToLower(question.Name.String())
	resp := dnsmessage.Message{Header: dnsmessage.Header{ID: q.Header.ID, Response: true, OpCode: q.Header.OpCode, RecursionDesired: q.Header.RecursionDesired}, Questions: q.Questions}
	ip, ok, until, ambiguous := lookup(name)
	remaining := until - time.Now().Unix()
	switch {
	case q.Header.OpCode != 0 || question.Class != dnsmessage.ClassINET || !strings.HasSuffix(name, suffix):
		resp.Header.RCode = dnsmessage.RCodeRefused
	case ambiguous || remaining <= 0:
		resp.Header.RCode = dnsmessage.RCodeServerFailure
	case !ok:
		resp.Header.Authoritative = true
		resp.Header.RCode = dnsmessage.RCodeNameError
	default:
		resp.Header.Authoritative = true
		if question.Type == dnsmessage.TypeA {
			ttl := int64(5)
			if remaining < ttl {
				ttl = remaining
			}
			resp.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: uint32(ttl)}, Body: &dnsmessage.AResource{A: ip}}}
		}
	}
	return resp.Pack()
}
func (d *dnsView) answer(b []byte) ([]byte, error) { return dnsAnswer(b, d.lookup) }
func startDNS(ctx context.Context, address string) (*dnsView, func(), error) {
	d := &dnsView{}
	stop, e := listenDNS(ctx, address, d.answer, d.Clear)
	return d, stop, e
}
func listenDNS(ctx context.Context, address string, answer func([]byte) ([]byte, error), clear func()) (func(), error) {
	if address == "" {
		return func() { clear() }, nil
	}
	a, e := netip.ParseAddrPort(address)
	if e != nil || !a.Addr().Is4() || !a.Addr().IsLoopback() || a.Port() == 0 {
		return nil, errors.New("DNS must bind a nonzero IPv4 loopback port")
	}
	udp, e := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(a))
	if e != nil {
		return nil, e
	}
	tcp, e := net.ListenTCP("tcp4", net.TCPAddrFromAddrPort(a))
	if e != nil {
		udp.Close()
		return nil, e
	}
	var once sync.Once
	stop := func() { once.Do(func() { clear(); udp.Close(); tcp.Close() }) }
	context.AfterFunc(ctx, stop)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, remote, e := udp.ReadFromUDP(buf)
			if e != nil {
				return
			}
			if !remote.IP.IsLoopback() {
				continue
			}
			if reply, e := answer(buf[:n]); e == nil {
				_, _ = udp.WriteToUDP(reply, remote)
			}
		}
	}()
	go func() {
		slots := make(chan struct{}, 32)
		for {
			c, e := tcp.AcceptTCP()
			if e != nil {
				return
			}
			select {
			case slots <- struct{}{}:
			default:
				c.Close()
				continue
			}
			go func(c *net.TCPConn) {
				defer c.Close()
				defer func() { <-slots }()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				if !c.RemoteAddr().(*net.TCPAddr).IP.IsLoopback() {
					return
				}
				var h [2]byte
				if _, e := io.ReadFull(c, h[:]); e != nil {
					return
				}
				n := int(binary.BigEndian.Uint16(h[:]))
				if n == 0 || n > 4096 {
					return
				}
				b := make([]byte, n)
				if _, e := io.ReadFull(c, b); e != nil {
					return
				}
				reply, e := answer(b)
				if e != nil {
					return
				}
				binary.BigEndian.PutUint16(h[:], uint16(len(reply)))
				_, _ = c.Write(append(h[:], reply...))
			}(c)
		}
	}()
	return stop, nil
}
