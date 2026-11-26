package path

import (
	"context"
	"testing"
	"time"

	"github.com/pion/ice/v4"
)

func TestRetainedPathCannotSendPastLease(t *testing.T) {
	// The connection is deliberately uninitialized: Send must reject before
	// calling it when the lease or the native session is no longer valid.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := &ICE{c: &ice.Conn{}, state: "selected", directContext: ctx, directUntil: time.Now().Add(-time.Second)}
	if p.Snapshot().Selected || p.Send([]byte{1}) == nil {
		t.Fatal("expired path available")
	}
	p.directUntil = time.Now().Add(time.Minute)
	cancel()
	if p.Snapshot().Selected || p.Send([]byte{1}) == nil {
		t.Fatal("canceled path available")
	}
	p.clear()
	if p.directContext != nil || !p.directUntil.IsZero() || p.Snapshot().Selected {
		t.Fatal("selection not cleared")
	}
}
