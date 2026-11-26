package packetqueue

import (
	"bytes"
	"encoding/binary"
	"sync/atomic"
	"testing"
	"time"
)

func packet() []byte {
	b := make([]byte, 28)
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	b[9] = 17
	return b
}
func TestQueueOwnershipBoundsAndClose(t *testing.T) {
	var writes, closes atomic.Int32
	d := New(func(p []byte) bool { writes.Add(1); p[20] = 8; return true }, func() { closes.Add(1) })
	b := packet()
	b[20] = 7
	if !d.Push(b) {
		t.Fatal("valid packet rejected")
	}
	b[20] = 9
	buf := [][]byte{make([]byte, 1280+16)}
	sizes := []int{0}
	if n, e := d.Read(buf, sizes, 16); e != nil || n != 1 || sizes[0] != 28 || buf[0][36] != 7 {
		t.Fatal("read ownership", n, e)
	}
	b = packet()
	if _, e := d.Write([][]byte{append(make([]byte, 8), b...)}, 8); e != nil || b[20] != 0 || writes.Load() != 1 {
		t.Fatal("write ownership")
	}
	for i := 0; i < Capacity; i++ {
		if !d.Push(packet()) {
			t.Fatal("queue capacity")
		}
	}
	if d.Push(packet()) {
		t.Fatal("unbounded queue")
	}
	v := packet()
	v[0] = 0x60
	if d.Push(v) {
		t.Fatal("IPv6 accepted")
	}
	v = packet()
	v[6] = 0x20
	if d.Push(v) {
		t.Fatal("fragment accepted")
	}
	if d.Drops() != 3 {
		t.Fatal("drop count")
	}
	d.Close()
	d.Close()
	if closes.Load() != 1 || d.Push(packet()) {
		t.Fatal("close ownership")
	}
	if _, e := d.Read(buf, sizes, 0); e == nil {
		t.Fatal("closed queue readable")
	}
	empty := New(nil, nil)
	done := make(chan error, 1)
	go func() { _, e := empty.Read(buf, sizes, 0); done <- e }()
	empty.Close()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("close did not cancel read")
		}
	case <-time.After(time.Second):
		t.Fatal("blocked read")
	}
	if !bytes.Equal(b, packet()) {
		t.Fatal("original buffer changed")
	}
}
