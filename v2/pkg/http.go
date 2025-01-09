package pkg

import (
	"crypto/tls"
	"github.com/chainreactors/utils/httputils"
	"net/http"
	"time"
)

var (
	maxRedirects     = 5
	HttpTimeout      time.Duration
	headers          = http.Header{"User-Agent": []string{httputils.GetRandomUA()}}
	DefaultTransport = &http.Transport{
		//TLSHandshakeTimeout : delay * time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS10,
			Renegotiation:      tls.RenegotiateOnceAsClient,
			InsecureSkipVerify: true,
		},
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
	conn := &http.Client{
		Transport: DefaultTransport,
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
	conn := &http.Client{
		Transport: DefaultTransport,
		Timeout:   time.Duration(delay) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return conn
}
