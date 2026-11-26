//go:build windows

package service

import (
	"context"
	"golang.org/x/sys/windows/svc"
)

type handler struct {
	parent context.Context
	fn     func(context.Context) error
	err    error
}

func (h *handler) Execute(args []string, requests <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(h.parent)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- h.fn(ctx) }()
	status := svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	changes <- status
	for {
		select {
		case e := <-done:
			h.err = e
			if e != nil {
				return false, 1
			}
			return false, 0
		case <-h.parent.Done():
			cancel()
			h.err = <-done
			return false, 0
		case r, ok := <-requests:
			if !ok {
				cancel()
				h.err = <-done
				return false, 0
			}
			switch r.Cmd {
			case svc.Interrogate:
				changes <- status
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending, WaitHint: 30000}
				cancel()
				h.err = <-done
				if h.err != nil {
					return false, 1
				}
				return false, 0
			}
		}
	}
}
func Run(ctx context.Context, fn func(context.Context) error) error {
	yes, e := svc.IsWindowsService()
	if e != nil {
		return e
	}
	if !yes {
		return fn(ctx)
	}
	h := &handler{parent: ctx, fn: fn}
	if e = svc.Run("NetworkEXAgent", h); e != nil {
		return e
	}
	return h.err
}
