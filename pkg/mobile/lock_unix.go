//go:build !windows

package mobile

import (
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"sync"
)

func lockRoot(root string) (func(), error) {
	fd, e := unix.Open(filepath.Join(root, ".mobile.lock"), unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), "mobile-lock")
	if f == nil {
		unix.Close(fd)
		return nil, errors.New("invalid mobile lock")
	}
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
		f.Close()
		return nil, errors.New("unsafe mobile lock")
	}
	if e = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); e != nil {
		f.Close()
		return nil, errors.New("another mobile profile operation is running")
	}
	var once sync.Once
	return func() { once.Do(func() { _ = unix.Flock(fd, unix.LOCK_UN); _ = f.Close() }) }, nil
}
