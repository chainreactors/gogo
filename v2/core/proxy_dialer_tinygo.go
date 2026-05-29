//go:build tinygo
// +build tinygo

package core

import (
	"net"
	"time"

	. "github.com/chainreactors/gogo/v2/pkg"
	"golang.org/x/net/context"
)

// configureRunnerProxy 仅把代理拨号器写入【本次运行的 RunnerOption】（per-instance），
// 不触碰任何包级全局。见 proxy_dialer.go 的说明。
func configureRunnerProxy(opt *RunnerOption, dialContext func(context.Context, string, string) (net.Conn, error)) {
	opt.ProxyDialContext = dialContext
	opt.ProxyDialTimeout = func(network, address string, duration time.Duration) (net.Conn, error) {
		ctx, _ := context.WithTimeout(context.Background(), duration)
		return dialContext(ctx, network, address)
	}
}
