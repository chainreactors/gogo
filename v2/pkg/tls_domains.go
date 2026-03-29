//go:build !tinygo
// +build !tinygo

package pkg

import "net/http"

func HasTLS(resp *http.Response) bool {
	return resp != nil && resp.TLS != nil
}

func peerDNSNames(resp *http.Response) []string {
	if resp == nil || resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		return nil
	}
	return resp.TLS.PeerCertificates[0].DNSNames
}
