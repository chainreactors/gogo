//go:build tinygo
// +build tinygo

package pkg

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/chainreactors/utils/httputils"
)

type HTTPTransport struct {
	DialContext func(context.Context, string, string) (net.Conn, error)
}

func (t *HTTPTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return http.DefaultTransport.RoundTrip(req)
}

var (
	maxRedirects     = 5
	HttpTimeout      time.Duration
	headers          = http.Header{"User-Agent": []string{httputils.GetRandomUA()}}
	DefaultTransport = &HTTPTransport{}
	errStopRedirect  = errors.New("stop redirect")
)

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

func HttpConnWithDialer(delay int, dialContext func(ctx context.Context, network, address string) (net.Conn, error)) *http.Client {
	transport := DefaultTransport
	if dialContext != nil {
		transport = &HTTPTransport{DialContext: dialContext}
	}
	conn := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(delay) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return errStopRedirect
			}
			return nil
		},
	}

	return conn
}

func HttpConnWithNoRedirect(delay int) *http.Client {
	return HttpConnWithNoRedirectWithDialer(delay, nil)
}

func HttpConnWithNoRedirectWithDialer(delay int, dialContext func(ctx context.Context, network, address string) (net.Conn, error)) *http.Client {
	transport := DefaultTransport
	if dialContext != nil {
		transport = &HTTPTransport{DialContext: dialContext}
	}
	conn := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(delay) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return errStopRedirect
		},
	}

	return conn
}
