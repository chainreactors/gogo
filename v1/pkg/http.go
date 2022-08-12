package pkg

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"time"
)

var Proxy func(*http.Request) (*url.URL, error)

func HttpConn(delay int) *http.Client {
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
		MaxIdleConns:        4000,
		IdleConnTimeout:     time.Duration(delay) * time.Second,
		DisableKeepAlives:   false,
	}

	conn := &http.Client{
		Transport:     tr,
		Timeout:       time.Duration(delay) * time.Second,
		CheckRedirect: checkRedirect,
	}

	return conn
}

var maxRedirects = 3
var checkRedirect = func(req *http.Request, via []*http.Request) error {
	//if !followRedirects {
	//	return http.ErrUseLastResponse
	//}
	if req.Header.Get("Referer") != "" {
		delete(req.Header, "Referer")
	}

	if len(via) > maxRedirects {
		return http.ErrUseLastResponse
	}

	return nil
}
