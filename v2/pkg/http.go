package pkg

import (
	"crypto/tls"
	"github.com/chainreactors/utils/httputils"
	"net"
	"net/http"
	"net/url"
	"time"
)

var (
	ProxyUrl         *url.URL
	Proxy            func(*http.Request) (*url.URL, error)
	maxRedirects     = 5
	HttpTimeout      time.Duration
	headers          = http.Header{"User-Agent": []string{httputils.GetRandomUA()}}
	DefaultTransport = &http.Transport{
		Proxy: Proxy,
		//TLSHandshakeTimeout : delay * time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS10,
			Renegotiation:      tls.RenegotiateOnceAsClient,
			InsecureSkipVerify: true,
		},
		DialContext: (&net.Dialer{
			Timeout:   HttpTimeout,
			KeepAlive: HttpTimeout,
			//DualStack: true,
		}).DialContext,
		MaxIdleConnsPerHost: 1,
		MaxIdleConns:        4000,
		IdleConnTimeout:     HttpTimeout,
		DisableKeepAlives:   false,
	}
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
	tr := DefaultTransport

	conn := &http.Client{
		Transport: tr,
		Timeout:   time.Duration(delay) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			//if !followRedirects {
			//	return http.ErrUseLastResponse
			//}
			//if req.URL.Host == "localhost" || req.URL.Host == "127.0.0.1" {
			//	return http.ErrUseLastResponse
			//}
			if len(via) >= maxRedirects {
				return http.ErrUseLastResponse
			}

			return nil
		},
	}

	return conn
}

func HttpConnWithNoRedirect(delay int) *http.Client {
	tr := &http.Transport{
		Proxy: Proxy,
		//TLSHandshakeTimeout : delay * time.Second,
		TLSClientConfig: &tls.Config{
			Renegotiation:      tls.RenegotiateOnceAsClient,
			InsecureSkipVerify: true,
		},
		DialContext: (&net.Dialer{
			//Timeout:   time.Duration(delay) * time.Second,
			//KeepAlive: time.Duration(delay) * time.Second,
			//DualStack: true,
		}).DialContext,
		MaxIdleConnsPerHost: 1,
		MaxIdleConns:        2000,
		IdleConnTimeout:     time.Duration(delay) * time.Second,
		DisableKeepAlives:   false,
	}

	conn := &http.Client{
		Transport: tr,
		Timeout:   time.Duration(delay) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return conn
}
