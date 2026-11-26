//go:build !windows

package ipc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"time"
)

func DefaultAddress() string {
	if runtime.GOOS == "darwin" {
		return "/var/run/network-ex/agent.sock"
	}
	return "/run/network-ex/agent.sock"
}
func checkParent(path string, server bool) error {
	if !filepath.IsAbs(path) {
		return errors.New("IPC socket path must be absolute")
	}
	st, e := os.Lstat(filepath.Dir(path))
	if e != nil {
		return e
	}
	if !st.IsDir() || st.Mode().Perm()&0022 != 0 {
		return errors.New("IPC socket parent must be a non-writable trusted directory")
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("cannot verify IPC parent owner")
	}
	if server && int(owner.Uid) != os.Geteuid() {
		return errors.New("IPC parent must be owned by daemon")
	}
	if !server && owner.Uid != 0 && int(owner.Uid) != os.Geteuid() {
		return errors.New("untrusted IPC directory owner")
	}
	return nil
}
func Listen(path string, gid int) (net.Listener, error) {
	if e := checkParent(path, true); e != nil {
		return nil, e
	}
	if st, e := os.Lstat(path); e == nil {
		if st.Mode()&os.ModeSocket == 0 {
			return nil, errors.New("IPC path is not a socket")
		}
		owner, ok := st.Sys().(*syscall.Stat_t)
		if !ok || int(owner.Uid) != os.Geteuid() {
			return nil, errors.New("IPC socket has untrusted owner")
		}
		c, e := net.DialTimeout("unix", path, time.Second)
		if e == nil {
			c.Close()
			return nil, errors.New("daemon already running")
		}
		if !errors.Is(e, syscall.ECONNREFUSED) {
			return nil, fmt.Errorf("cannot verify stale socket: %w", e)
		}
		if e = os.Remove(path); e != nil {
			return nil, e
		}
	} else if !os.IsNotExist(e) {
		return nil, e
	}
	l, e := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if e != nil {
		return nil, e
	}
	l.SetUnlinkOnClose(true)
	if gid >= 0 {
		if e = os.Chown(path, -1, gid); e != nil {
			l.Close()
			return nil, e
		}
	}
	if e = os.Chmod(path, 0660); e != nil {
		l.Close()
		return nil, e
	}
	return l, nil
}
func Dial(ctx context.Context, path string) (net.Conn, error) {
	if e := checkParent(path, false); e != nil {
		return nil, e
	}
	st, e := os.Lstat(path)
	if e != nil {
		return nil, e
	}
	if st.Mode()&os.ModeSocket == 0 || st.Mode().Perm()&0007 != 0 {
		return nil, errors.New("invalid or publicly accessible IPC socket")
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != 0 && int(owner.Uid) != os.Geteuid() {
		return nil, errors.New("untrusted IPC socket owner")
	}
	return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", path)
}
