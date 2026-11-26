//go:build windows

package mobile

import "errors"

func lockRoot(root string) (func(), error) {
	return nil, errors.New("mobile native adapter is unavailable on Windows")
}
