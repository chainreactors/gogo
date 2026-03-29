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
	conn := &http.Client{
		Transport: DefaultTransport,
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
	conn := &http.Client{
		Transport: DefaultTransport,
		Timeout:   time.Duration(delay) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return errStopRedirect
		},
	}

	return conn
}
