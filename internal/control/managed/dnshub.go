package managed

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/xzcode/network-ex/pkg/protocol"
)

type DNSHub struct {
	mu    sync.RWMutex
	views map[string]*dnsView
}

func StartDNSHub(ctx context.Context, address string) (*DNSHub, func(), error) {
	h := &DNSHub{views: make(map[string]*dnsView)}
	stop, e := listenDNS(ctx, address, func(b []byte) ([]byte, error) { return dnsAnswer(b, h.lookup) }, h.clear)
	if e != nil {
		return nil, nil, e
	}
	return h, stop, nil
}
func (h *DNSHub) view(profile string) (*dnsView, error) {
	if !protocol.ValidDNSLabel(profile) {
		return nil, errors.New("invalid DNS profile")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	d := h.views[profile]
	if d == nil {
		if len(h.views) >= 8 {
			return nil, errors.New("DNS profile limit")
		}
		d = &dnsView{}
		h.views[profile] = d
	}
	return d, nil
}
func (h *DNSHub) clear() {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, d := range h.views {
		d.Clear()
	}
}
func (h *DNSHub) lookup(name string) (ip [4]byte, found bool, until int64, ambiguous bool) {
	if !strings.HasSuffix(name, suffix) {
		return
	}
	labels := strings.Split(strings.TrimSuffix(name, suffix), ".")
	now := time.Now().Unix()
	h.mu.RLock()
	defer h.mu.RUnlock()
	if len(labels) == 2 {
		if d := h.views[labels[1]]; d != nil {
			return d.lookup(labels[0] + suffix)
		}
		// Unknown profile is not a valid local DNS zone.
		return ip, false, now + 5, false
	}
	if len(labels) != 1 {
		return ip, false, now + 5, false
	}
	var activeUntil int64
	for _, d := range h.views {
		a, ok, exp, _ := d.lookup(name)
		if exp <= now {
			continue
		}
		if activeUntil == 0 || exp < activeUntil {
			activeUntil = exp
		}
		if !ok {
			continue
		}
		if found {
			return ip, false, 0, true
		}
		ip, found, until = a, true, exp
	}
	if !found {
		until = activeUntil
	}
	return
}
