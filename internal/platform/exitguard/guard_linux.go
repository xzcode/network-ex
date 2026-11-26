//go:build linux

package exitguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/xzcode/network-ex/pkg/protocol"
)

var ifaceRE = regexp.MustCompile("^[A-Za-z][A-Za-z0-9_-]{0,14}$")

// Install a narrowly scoped output filter before enabling any exit routes.
// The main/default routes and IPv6 are never modified. The named table is
// exclusive: a stale table after an abnormal exit must be inspected by root.
func Install(ctx context.Context, iface, controlHost string, raw []string) (func() error, error) {
	if len(raw) == 0 {
		return func() error { return nil }, nil
	}
	if !ifaceRE.MatchString(iface) {
		return nil, errors.New("invalid exit interface")
	}
	targets, e := protocol.ValidateExitTargets(raw)
	if e != nil {
		return nil, e
	}
	resolve, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ips, e := net.DefaultResolver.LookupNetIP(resolve, "ip4", controlHost)
	if e != nil || len(ips) == 0 {
		return nil, errors.New("cannot verify management address before exit protection")
	}
	for _, ip := range ips {
		ip = ip.Unmap()
		for _, p := range targets {
			if p.Contains(ip) {
				return nil, errors.New("exit target overlaps management endpoint")
			}
		}
	}
	name := "nexexit_" + strings.ReplaceAll(iface, "-", "_")
	vals := []string{}
	for _, p := range targets {
		vals = append(vals, p.Addr().String())
	}
	script := fmt.Sprintf("create table inet %s\nadd chain inet %s output { type filter hook output priority -150; policy accept; }\nadd rule inet %s output ip daddr { %s } oifname != \"%s\" counter drop\n", name, name, name, strings.Join(vals, ", "), iface)
	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	if b, e := cmd.CombinedOutput(); e != nil {
		return nil, fmt.Errorf("cannot install exit protection (inspect existing table %s): %w: %s", name, e, strings.TrimSpace(string(b)))
	}
	var once sync.Once
	var closeErr error
	return func() error {
		once.Do(func() {
			c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			b, e := exec.CommandContext(c, "nft", "delete", "table", "inet", name).CombinedOutput()
			if e != nil {
				closeErr = fmt.Errorf("remove exit protection %s: %w: %s", name, e, strings.TrimSpace(string(b)))
			}
		})
		return closeErr
	}, nil
}
