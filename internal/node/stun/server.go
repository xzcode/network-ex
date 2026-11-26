package stunserver

import (
	"context"
	"net"
	"time"

	"github.com/pion/stun/v4"
)

// Binding-only IPv4 STUN. Limit response to the observed source tuple
// observed by UDP and no larger than a normal request plus a bounded header.
func Serve(ctx context.Context, c *net.UDPConn) error {
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	defer c.Close()
	buf := make([]byte, 512)
	window := time.Now()
	count := 0
	for {
		n, addr, e := c.ReadFromUDP(buf)
		if e != nil {
			if ctx.Err() != nil {
				return nil
			}
			return e
		}
		now := time.Now()
		if now.Sub(window) >= time.Second {
			window = now
			count = 0
		}
		count++
		if count > 2000 {
			continue
		}
		if n < 20 || n >= len(buf) || !stun.IsMessage(buf[:n]) {
			continue
		}
		msg := &stun.Message{Raw: append([]byte(nil), buf[:n]...)}
		if msg.Decode() != nil || msg.Type != stun.BindingRequest {
			continue
		}
		resp, e := stun.Build(stun.BindingSuccess, stun.XORMappedAddress{IP: addr.IP, Port: addr.Port})
		if e != nil {
			continue
		}
		resp.TransactionID = msg.TransactionID
		resp.WriteTransactionID()
		if len(resp.Raw) > n+32 {
			continue
		}
		c.WriteToUDP(resp.Raw, addr)
	}
}
