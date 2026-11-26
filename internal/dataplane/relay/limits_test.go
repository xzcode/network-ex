package relay

import (
	"github.com/xzcode/network-ex/pkg/protocol"
	"testing"
	"time"
)

func TestNodeLimiter(t *testing.T) {
	var l nodeLimiter
	l.set(protocol.NodeLimits{MaxConnections: 2, BytesPerSecond: 65536})
	if !l.admit() || !l.admit() || l.admit() {
		t.Fatal("connection cap not enforced")
	}
	l.release()
	if !l.admit() {
		t.Fatal("released capacity not reusable")
	}
	if !l.allow(65536) || l.allow(65536) {
		t.Fatal("aggregate byte bucket not enforced")
	}
	l.mu.Lock()
	l.at = time.Now().Add(-time.Second)
	l.mu.Unlock()
	if !l.allow(65536) {
		t.Fatal("bucket did not refill")
	}
	l.set(protocol.NodeLimits{MaxConnections: 3, BytesPerSecond: 131072})
	if !l.admit() || l.admit() {
		t.Fatal("dynamic connection cap not applied")
	}
	if l.stats().Connections != 3 {
		t.Fatal("incorrect connection gauge")
	}
}
