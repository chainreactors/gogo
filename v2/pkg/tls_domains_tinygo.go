//go:build tinygo
// +build tinygo

package pkg

import "net/http"

func HasTLS(resp *http.Response) bool {
	return false
}

func peerDNSNames(resp *http.Response) []string {
	return nil
}
