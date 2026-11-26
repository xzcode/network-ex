//go:build !windows

package localfile

import (
	"errors"
	"os"
)

func Check(path string, dir bool, max int64) error {
	st, e := os.Lstat(path)
	if e != nil {
		return e
	}
	if (dir && !st.IsDir()) || (!dir && !st.Mode().IsRegular()) || st.Mode().Perm()&0077 != 0 || (!dir && max > 0 && st.Size() > max) {
		return errors.New("unsafe private file/directory permissions or size")
	}
	return nil
}
