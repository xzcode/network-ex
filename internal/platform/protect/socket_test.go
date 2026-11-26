package protect

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestRejectedSocketNeverConnects(t *testing.T) {
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	var count atomic.Int64
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	deny := Protector(func(fd int) bool { count.Add(1); return false })
	if c, e := deny.Dial(ctx, "tcp4", l.Addr().String()); e == nil {
		c.Close()
		t.Fatal("unprotected socket connected")
	}
	if count.Load() == 0 {
		t.Fatal("protection callback not invoked")
	}
	allow := Protector(func(fd int) bool { return fd >= 0 })
	c, e := allow.Dial(ctx, "tcp4", l.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	c.Close()
}
