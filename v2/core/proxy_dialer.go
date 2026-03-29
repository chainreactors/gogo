//go:build !tinygo
// +build !tinygo

package core

import (
	"net"
	"time"

	. "github.com/chainreactors/gogo/v2/pkg"
	neuhttp "github.com/chainreactors/neutron/protocols/http"
	"golang.org/x/net/context"
)

func installProxyDialer(dialContext func(context.Context, string, string) (net.Conn, error)) {
	neuhttp.DefaultTransport.DialContext = dialContext
	DefaultTransport.DialContext = dialContext
	ProxyDialTimeout = func(network, address string, duration time.Duration) (net.Conn, error) {
		ctx, _ := context.WithTimeout(context.Background(), duration)
		return dialContext(ctx, network, address)
	}
}
