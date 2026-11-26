//go:build !windows

package service

import "context"

func Run(ctx context.Context, fn func(context.Context) error) error { return fn(ctx) }
