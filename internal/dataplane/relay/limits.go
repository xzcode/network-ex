package relay

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/xzcode/network-ex/pkg/protocol"
)

type nodeLimiter struct {
	mu            sync.Mutex
	rate          int64
	tokens        float64
	at            time.Time
	cap           atomic.Int64
	active        atomic.Int64
	in, out, drop atomic.Uint64
}

func (l *nodeLimiter) set(v protocol.NodeLimits) {
	if v.MaxConnections < 2 || v.MaxConnections > maxPeers || v.BytesPerSecond < 65536 || v.BytesPerSecond > 1<<30 {
		return
	}
	l.cap.Store(int64(v.MaxConnections))
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.rate != v.BytesPerSecond {
		if l.rate == 0 {
			l.tokens = float64(v.BytesPerSecond)
		} else if l.tokens > float64(v.BytesPerSecond) {
			l.tokens = float64(v.BytesPerSecond)
		}
		l.rate = v.BytesPerSecond
		l.at = time.Now()
	}
}
func (l *nodeLimiter) admit() bool {
	for {
		n := l.active.Load()
		cap := l.cap.Load()
		if cap == 0 {
			cap = maxPeers
		}
		if n >= cap {
			return false
		}
		if l.active.CompareAndSwap(n, n+1) {
			return true
		}
	}
}
func (l *nodeLimiter) release() { l.active.Add(-1) }
func (l *nodeLimiter) allow(n int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.rate == 0 {
		return true
	}
	now := time.Now()
	l.tokens += now.Sub(l.at).Seconds() * float64(l.rate)
	l.at = now
	if l.tokens > float64(l.rate) {
		l.tokens = float64(l.rate)
	}
	if l.tokens < float64(n) {
		return false
	}
	l.tokens -= float64(n)
	return true
}
func (l *nodeLimiter) stats() protocol.NodeStats {
	return protocol.NodeStats{Connections: int(l.active.Load()), Ingress: l.in.Load(), Egress: l.out.Load(), Dropped: l.drop.Load()}
}
func (s *Server) SetLimits(v protocol.NodeLimits) { s.limiter.set(v) }
func (s *Server) Stats() protocol.NodeStats       { return s.limiter.stats() }
