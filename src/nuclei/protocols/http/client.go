package http

import (
	"crypto/tls"
	"net/http"
	"net/http/cookiejar"
	"time"
)

type Configuration struct {
	Timeout         int
	FollowRedirects bool
	MaxRedirects    int
	CookieReuse     bool
}

var Defaultoption = Configuration{
	2,
	true,
	3,
	false,
}

func createClient(opt *Configuration) *http.Client {
	tr := &http.Transport{
		//TLSHandshakeTimeout : delay * time.Second,
		TLSClientConfig: &tls.Config{
			Renegotiation:      tls.RenegotiateOnceAsClient,
			InsecureSkipVerify: true,
		},
		DisableKeepAlives: true,
	}
	var jar *cookiejar.Jar
	if opt.CookieReuse {
		jar, _ = cookiejar.New(nil)
	}
	client := &http.Client{
		Transport:     tr,
		Timeout:       time.Duration(opt.Timeout) * time.Second,
		CheckRedirect: makeCheckRedirectFunc(opt.FollowRedirects, opt.MaxRedirects),
	}
	if jar != nil {
		client.Jar = jar
	}
	return client
}

const defaultMaxRedirects = 10

type checkRedirectFunc func(req *http.Request, via []*http.Request) error

func makeCheckRedirectFunc(followRedirects bool, maxRedirects int) checkRedirectFunc {
	return func(req *http.Request, via []*http.Request) error {
		if !followRedirects {
			return http.ErrUseLastResponse
		}
		if maxRedirects == 0 {
			if len(via) > defaultMaxRedirects {
				return http.ErrUseLastResponse
			}
			return nil
		}

		if len(via) > maxRedirects {
			return http.ErrUseLastResponse
		}
		return nil
	}
}
