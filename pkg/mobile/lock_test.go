//go:build !windows

package mobile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProfileLock(t *testing.T) {
	root := t.TempDir()
	if e := os.Chmod(root, 0700); e != nil {
		t.Fatal(e)
	}
	a, e := lockRoot(root)
	if e != nil {
		t.Fatal(e)
	}
	if b, e := lockRoot(root); e == nil {
		b()
		t.Fatal("second profile lock acquired")
	}
	if e = Forget(root); e == nil {
		t.Fatal("forget while session locked")
	}
	a()
	b, e := lockRoot(root)
	if e != nil {
		t.Fatal(e)
	}
	b()
	if e = os.WriteFile(filepath.Join(root, "private-ca.pem"), []byte("fixture"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = Forget(root); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(filepath.Join(root, "private-ca.pem")); !os.IsNotExist(e) {
		t.Fatal("CA remained")
	}
}
