package pkg

import (
	"bytes"
	"net/http"
	"strings"

	"github.com/chainreactors/parsers"
	"github.com/chainreactors/parsers/iutils"
)

func CollectSocketInfo(result *Result, socketContent []byte) {
	result.Content = bytes.ToLower(socketContent)
	ishttp, statuscode := GetStatusCode(socketContent)
	if ishttp {
		result.Httpresp = parsers.NewResponseWithRaw(socketContent)
		result.Status = statuscode
		result.Protocol = "http"
		result.IsHttp = true
		result.Language = result.Httpresp.Language
		result.Midware = result.Httpresp.Server
		result.Title = result.Httpresp.Title
		result.HasTitle = result.Httpresp.HasTitle
	} else {
		if title := parsers.MatchTitle(socketContent); title != "" {
			result.HasTitle = true
			result.Title = title
		} else {
			result.Title = parsers.MatchTitle(socketContent)
		}
	}
	result.AddExtracts(Extractors.Extract(string(socketContent)))
}

func CollectHttpInfo(result *Result, resp *http.Response) {
	if resp == nil {
		return
	}
	result.IsHttp = true
	result.Httpresp = parsers.NewResponse(resp)
	result.Content = bytes.ToLower(result.Httpresp.Raw)
	result.Status = iutils.ToString(resp.StatusCode)
	result.Language = result.Httpresp.Language
	result.Midware = result.Httpresp.Server
	result.Title = result.Httpresp.Title
	result.AddExtracts(Extractors.Extract(string(result.Httpresp.Raw)))
}

// GetStatusCode 从socket中获取http状态码
func GetStatusCode(content []byte) (bool, string) {
	if len(content) > 12 && bytes.HasPrefix(content, []byte("HTTP")) {
		return true, string(content[9:12])
	}
	return false, "tcp"
}

func FormatCertDomains(domains []string) []string {
	var hosts []string
	for _, domain := range domains {
		if strings.HasPrefix(domain, "*.") {
			domain = strings.Trim(domain, "*.")
		}
		hosts = append(hosts, domain)
	}
	return iutils.StringsUnique(hosts)
}
