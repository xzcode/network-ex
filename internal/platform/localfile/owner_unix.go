//go:build !windows

package localfile

import (
	"errors"
	"os"
	"syscall"
)

func CheckOwner(path string) error {
	st, e := os.Lstat(path)
	if e != nil {
		return e
	}
	v, ok := st.Sys().(*syscall.Stat_t)
	if !ok || int(v.Uid) != os.Geteuid() {
		return errors.New("private service root must be owned by daemon")
	}
	return nil
}
