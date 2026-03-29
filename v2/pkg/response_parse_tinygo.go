//go:build tinygo
// +build tinygo

package pkg

import (
	"bytes"
	"net/http"
	"strconv"
	"strings"

	"github.com/chainreactors/parsers"
	"github.com/chainreactors/utils/httputils"
)

func newResponseFromRaw(raw []byte) *parsers.Response {
	if len(raw) == 0 {
		return nil
	}

	_, header, _ := httputils.SplitHttpRaw(raw)
	lines := bytes.Split(header, []byte{'\n'})
	if len(lines) == 0 {
		return nil
	}

	statusCode := 0
	statusLine := strings.TrimSpace(string(lines[0]))
	if ok, status := GetStatusCode(raw); ok {
		statusCode, _ = strconv.Atoi(status)
	}

	server := ""
	for _, line := range lines[1:] {
		text := strings.TrimSpace(string(line))
		if strings.HasPrefix(strings.ToLower(text), "server:") {
			server = strings.TrimSpace(text[len("server:"):])
			break
		}
	}

	content := parsers.NewContent(raw)
	result := &parsers.Response{
		Server:  server,
		History: nil,
		Resp: &http.Response{
			Status:     statusLine,
			StatusCode: statusCode,
			Header:     http.Header{},
		},
		Content: content,
	}

	if title := parsers.MatchTitle(raw); title != "" {
		result.HasTitle = true
		result.Title = title
	} else {
		result.Title = parsers.MatchCharacter(raw)
	}

	return result
}

func newResponseFromHTTP(resp *http.Response, size int64) *parsers.Response {
	return parsers.NewResponse(resp, size)
}
