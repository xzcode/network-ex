package protect

import (
	"context"
	"errors"
	"net"
	"syscall"
)

// Protector is supplied only by an OS VPN integration. A rejected socket
// cannot be used. No unsafe global override of the Go network stack.
type Protector func(int) bool

func (p Protector) Control(network, address string, c syscall.RawConn) error {
	if p == nil {
		return nil
	}
	ok := false
	e := c.Control(func(fd uintptr) { ok = p(int(fd)) })
	if e != nil {
		return e
	}
	if !ok {
		return errors.New("VPN platform rejected underlay socket protection")
	}
	return nil
}
func (p Protector) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	d := net.Dialer{Control: p.Control}
	return d.DialContext(ctx, network, address)
}
