//go:build !tinygo
// +build !tinygo

package pkg

import (
	"net/http"

	"github.com/chainreactors/parsers"
)

func newResponseFromRaw(raw []byte) *parsers.Response {
	return parsers.NewResponseWithRaw(raw)
}

func newResponseFromHTTP(resp *http.Response, size int64) *parsers.Response {
	return parsers.NewResponse(resp, size)
}
