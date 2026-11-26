//go:build !linux

package exitguard

import (
	"context"
	"errors"
)

func Install(ctx context.Context, iface, controlHost string, raw []string) (func() error, error) {
	if len(raw) > 0 {
		return nil, errors.New("selective exit protection currently requires Linux nftables")
	}
	return func() error { return nil }, nil
}
