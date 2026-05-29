//go:build !tinygo
// +build !tinygo

package core

import (
	"net"
	"time"

	. "github.com/chainreactors/gogo/v2/pkg"
	"golang.org/x/net/context"
)

// configureRunnerProxy 仅把代理拨号器写入【本次运行的 RunnerOption】（per-instance），
// 不触碰任何包级全局。socket/http 扫描经此 dialer 工作，因此并发的不同 Runner
// 各自携带各自的 dialer，互不覆盖。
//
// 注意：gogo CLI 的 neutron exploit 走的是“编译期烘焙进全局 pkg.TemplateMap 的
// client”，其 dialer 由 pkg.ExecuterOptions 决定——那是 CLI 单进程的全局，
// 不在本函数内设置（见 runner.go 的显式处理）。
func configureRunnerProxy(opt *RunnerOption, dialContext func(context.Context, string, string) (net.Conn, error)) {
	opt.ProxyDialContext = dialContext
	opt.ProxyDialTimeout = func(network, address string, duration time.Duration) (net.Conn, error) {
		ctx, _ := context.WithTimeout(context.Background(), duration)
		return dialContext(ctx, network, address)
	}
}
