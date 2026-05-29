//go:build !tinygo
// +build !tinygo

package pkg

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"github.com/chainreactors/utils/httputils"
	"github.com/chainreactors/utils/httpx"
)

var (
	maxRedirects = 5
	HttpTimeout  time.Duration
	headers      = http.Header{"User-Agent": []string{httputils.GetRandomUA()}}
	// DefaultTransport 仅作为不可变的默认配置参考保留；运行时不再被改写，
	// 也不再作为客户端共享 transport（每次构造经 utils/httpx 返回全新实例，
	// 确保并发下不同代理互不干扰）。
	DefaultTransport = &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS10,
			Renegotiation:      tls.RenegotiateOnceAsClient,
			InsecureSkipVerify: true,
		},
		MaxIdleConnsPerHost: 1,
		MaxIdleConns:        4000,
		DisableKeepAlives:   false,
	}
)

// gogoClientConfig 返回 gogo 默认的 httpx.ClientConfig（可注入 dialContext）。
func gogoClientConfig(delay int, followRedirects bool, dialContext httpx.DialContextFunc) httpx.ClientConfig {
	return httpx.ClientConfig{
		Timeout:             time.Duration(delay) * time.Second,
		FollowRedirects:     followRedirects,
		MaxRedirects:        maxRedirects,
		InsecureSkipVerify:  true,
		TLSConfig:           &tls.Config{MinVersion: tls.VersionTLS10, Renegotiation: tls.RenegotiateOnceAsClient, InsecureSkipVerify: true},
		DialContext:         dialContext,
		MaxIdleConns:        4000,
		MaxIdleConnsPerHost: 1,
		IdleConnTimeout:     HttpTimeout,
	}
}

func HTTPGet(client *http.Client, url string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header = headers
	return client.Do(req)
}

func HttpConn(delay int) *http.Client {
	return HttpConnWithDialer(delay, nil)
}

// HttpConnWithDialer 创建一个 http.Client。dialContext 非 nil 时作为 Transport
// 的 DialContext（用于代理）。每次返回全新实例，不读写任何全局状态。
func HttpConnWithDialer(delay int, dialContext func(ctx context.Context, network, address string) (net.Conn, error)) *http.Client {
	return httpx.NewHTTPClient(gogoClientConfig(delay, true, dialContext))
}

func HttpConnWithNoRedirect(delay int) *http.Client {
	return HttpConnWithNoRedirectWithDialer(delay, nil)
}

// HttpConnWithNoRedirectWithDialer 同 HttpConnWithDialer，但禁止重定向。
func HttpConnWithNoRedirectWithDialer(delay int, dialContext func(ctx context.Context, network, address string) (net.Conn, error)) *http.Client {
	return httpx.NewHTTPClient(gogoClientConfig(delay, false, dialContext))
}
