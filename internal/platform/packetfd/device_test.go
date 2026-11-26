//go:build linux && !android

package packetfd

import (
	"bytes"
	"golang.org/x/sys/unix"
	"testing"
	"time"
)

func TestDetachedFDLifecycle(t *testing.T) {
	f, e := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer unix.Close(f[1])
	d, e := New(f[0], "mobile0")
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	b := []byte{1, 2, 3, 4}
	if _, e = unix.Write(f[1], b); e != nil {
		t.Fatal(e)
	}
	buf := [][]byte{make([]byte, 64)}
	sizes := []int{0}
	if n, e := d.Read(buf, sizes, 4); e != nil || n != 1 || !bytes.Equal(buf[0][4:4+sizes[0]], b) {
		t.Fatal("fd read", n, e)
	}
	if _, e = d.Write([][]byte{{0, 0, 5, 6}}, 2); e != nil {
		t.Fatal(e)
	}
	out := make([]byte, 64)
	if n, e := unix.Read(f[1], out); e != nil || !bytes.Equal(out[:n], []byte{5, 6}) {
		t.Fatal("fd write", n, e)
	}
	done := make(chan error, 1)
	go func() { _, e := d.Read(buf, sizes, 0); done <- e }()
	time.Sleep(20 * time.Millisecond)
	if e = d.Close(); e != nil {
		t.Fatal(e)
	}
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("read remained successful after close")
		}
	case <-time.After(time.Second):
		t.Fatal("FD close did not cancel reader")
	}
}
