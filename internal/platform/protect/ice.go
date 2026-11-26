package protect

import (
	"context"
	"errors"
	"net"
	"time"

	pion "github.com/pion/transport/v5"
	"github.com/pion/transport/v5/stdnet"
)

// ICENet wraps every Pion transport socket creation path. M8 permits UDP4
// candidates only; TCP/TURN transports fail closed rather than creating
// unprotected sockets. Host enumeration and OS DNS resolution use stdnet;
// the native application UID must also be excluded from its own VPN.
type ICENet struct {
	*stdnet.Net
	p Protector
}

var _ pion.Net = (*ICENet)(nil)

func NewICENet(p Protector) (*ICENet, error) {
	if p == nil {
		return nil, errors.New("ICE socket protector required")
	}
	base, e := stdnet.NewNet()
	if e != nil {
		return nil, e
	}
	return &ICENet{Net: base, p: p}, nil
}
func udp4(network string) bool { return network == "udp" || network == "udp4" }
func (n *ICENet) ListenPacket(network, address string) (net.PacketConn, error) {
	if !udp4(network) {
		return nil, errors.New("protected ICE supports UDP4 only")
	}
	lc := net.ListenConfig{Control: n.p.Control}
	return lc.ListenPacket(context.Background(), "udp4", address)
}
func (n *ICENet) ListenUDP(network string, addr *net.UDPAddr) (pion.UDPConn, error) {
	if addr == nil {
		addr = &net.UDPAddr{IP: net.IPv4zero}
	}
	c, e := n.ListenPacket(network, addr.String())
	if e != nil {
		return nil, e
	}
	u, ok := c.(*net.UDPConn)
	if !ok {
		c.Close()
		return nil, errors.New("expected protected UDP socket")
	}
	return u, nil
}
func (n *ICENet) Dial(network, address string) (net.Conn, error) {
	if !udp4(network) {
		return nil, errors.New("protected ICE supports UDP4 only")
	}
	d := net.Dialer{Control: n.p.Control, Timeout: 5 * time.Second}
	return d.Dial("udp4", address)
}
func (n *ICENet) DialUDP(network string, laddr, raddr *net.UDPAddr) (pion.UDPConn, error) {
	if !udp4(network) || raddr == nil {
		return nil, errors.New("protected ICE requires UDP4 remote address")
	}
	d := net.Dialer{LocalAddr: laddr, Control: n.p.Control, Timeout: 5 * time.Second}
	c, e := d.Dial("udp4", raddr.String())
	if e != nil {
		return nil, e
	}
	u, ok := c.(*net.UDPConn)
	if !ok {
		c.Close()
		return nil, errors.New("expected protected UDP socket")
	}
	return u, nil
}
func (n *ICENet) ListenTCP(network string, addr *net.TCPAddr) (pion.TCPListener, error) {
	return nil, errors.New("ICE TCP disabled")
}
func (n *ICENet) DialTCP(network string, laddr, raddr *net.TCPAddr) (pion.TCPConn, error) {
	return nil, errors.New("ICE TCP disabled")
}

type protectedDialer struct{ d net.Dialer }

func (d protectedDialer) Dial(network, address string) (net.Conn, error) {
	if !udp4(network) {
		return nil, errors.New("ICE TCP disabled")
	}
	return d.d.Dial("udp4", address)
}
func (n *ICENet) CreateDialer(d *net.Dialer) pion.Dialer {
	var copy net.Dialer
	if d != nil {
		copy = *d
	}
	// ControlContext would take precedence over Control, so clear it.
	copy.ControlContext = nil
	copy.Control = n.p.Control
	if copy.Timeout <= 0 || copy.Timeout > 5*time.Second {
		copy.Timeout = 5 * time.Second
	}
	return protectedDialer{copy}
}

// Transport v5 adds a listen-config factory. Do not inherit stdnet's
// implementation: that would create unprotected sockets.
type protectedListenConfig struct{ c net.ListenConfig }

func (c protectedListenConfig) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	return nil, errors.New("ICE TCP listener disabled")
}
func (c protectedListenConfig) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	if !udp4(network) {
		return nil, errors.New("protected ICE supports UDP4 only")
	}
	return c.c.ListenPacket(ctx, "udp4", address)
}
func (n *ICENet) CreateListenConfig(lc *net.ListenConfig) pion.ListenConfig {
	var c net.ListenConfig
	if lc != nil {
		c = *lc
	}
	c.Control = n.p.Control
	return protectedListenConfig{c}
}
