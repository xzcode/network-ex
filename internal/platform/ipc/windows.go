//go:build windows

package ipc

import (
	"context"
	"errors"
	"golang.org/x/sys/windows"
	"net"
	"strings"

	"github.com/Microsoft/go-winio"
)

func DefaultAddress() string { return `\\.\pipe\NetworkEXAgent` }
func valid(path string) bool {
	return strings.HasPrefix(path, `\\.\pipe\NetworkEXAgent`) && !strings.ContainsAny(strings.TrimPrefix(path, `\\.\pipe\NetworkEXAgent`), `\/: `)
}
func Listen(path string, gid int) (net.Listener, error) {
	if !valid(path) {
		return nil, errors.New("invalid local Network EX named pipe")
	}
	// Only LocalSystem and elevated local administrators are authorized.
	return winio.ListenPipe(path, &winio.PipeConfig{SecurityDescriptor: "D:P(A;;GA;;;SY)(A;;GA;;;BA)", MessageMode: false, InputBufferSize: 65536, OutputBufferSize: 65536})
}
func Dial(ctx context.Context, path string) (net.Conn, error) {
	if !valid(path) {
		return nil, errors.New("invalid local Network EX named pipe")
	}
	c, e := winio.DialPipeContext(ctx, path)
	if e != nil {
		return nil, e
	}
	// Do not send invitation credentials to a pipe created by an untrusted local user.
	f, ok := c.(interface{ Fd() uintptr })
	if !ok {
		c.Close()
		return nil, errors.New("cannot verify named pipe owner")
	}
	sd, e := windows.GetSecurityInfo(windows.Handle(f.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if e != nil {
		c.Close()
		return nil, errors.New("cannot verify named pipe owner")
	}
	owner, _, e := sd.Owner()
	sy, se := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	ba, be := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if e != nil || se != nil || be != nil || owner == nil || (!owner.Equals(sy) && !owner.Equals(ba)) {
		c.Close()
		return nil, errors.New("untrusted named pipe owner")
	}
	return c, nil
}
