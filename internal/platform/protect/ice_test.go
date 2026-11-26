package protect

import (
	"net"
	"sync/atomic"
	"testing"
)

func TestICENetSocketPaths(t *testing.T) {
	var denied atomic.Int64
	n, e := NewICENet(func(fd int) bool { denied.Add(1); return false })
	if e != nil {
		t.Fatal(e)
	}
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
	if c, e := n.ListenPacket("udp4", "127.0.0.1:0"); e == nil {
		c.Close()
		t.Fatal("unprotected packet listener")
	}
	if c, e := n.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}); e == nil {
		c.Close()
		t.Fatal("unprotected UDP listener")
	}
	if c, e := n.DialUDP("udp4", nil, addr); e == nil {
		c.Close()
		t.Fatal("unprotected UDP dial")
	}
	if c, e := n.Dial("udp4", addr.String()); e == nil {
		c.Close()
		t.Fatal("unprotected dial")
	}
	if c, e := n.CreateDialer(&net.Dialer{}).Dial("udp4", addr.String()); e == nil {
		c.Close()
		t.Fatal("unprotected custom dial")
	}
	if denied.Load() != 5 {
		t.Fatalf("expected five protection calls, got %d", denied.Load())
	}
	if c, e := n.ListenTCP("tcp4", nil); e == nil {
		c.Close()
		t.Fatal("TCP accepted")
	}
	if c, e := n.DialTCP("tcp4", nil, nil); e == nil {
		c.Close()
		t.Fatal("TCP dial accepted")
	}
	ok, e := NewICENet(func(fd int) bool { return fd >= 0 })
	if e != nil {
		t.Fatal(e)
	}
	c, e := ok.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	c.Close()
}
