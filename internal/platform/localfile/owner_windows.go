//go:build windows

package localfile

func CheckOwner(path string) error { return Check(path, true, 0) }
