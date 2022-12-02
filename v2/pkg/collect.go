package pkg

import (
	"github.com/chainreactors/gogo/v2/pkg/utils"
	"github.com/chainreactors/parsers"
	"net/http"
	"strings"
)

func CollectSocketInfo(result *Result, socketContent []byte) {
	result.Content = strings.ToLower(string(socketContent))
	content := string(socketContent)
	ishttp, statuscode := GetStatusCode(content)
	if ishttp {
		result.Httpresp = parsers.NewResponseWithRaw(socketContent)
		result.Status = statuscode
		result.Protocol = "http"
		result.IsHttp = true
		result.Language = result.Httpresp.Language
		result.Midware = result.Httpresp.Server
		result.Title = result.Httpresp.Title
	} else {
		result.Title = parsers.MatchTitle(content)
	}
	result.AddExtracts(Extractors.Extract(content))
}

func CollectHttpInfo(result *Result, resp *http.Response) {
	if resp != nil {
		result.Httpresp = parsers.NewResponse(resp)
		result.Content = strings.ToLower(string(result.Httpresp.RawContent))
		result.Protocol = resp.Request.URL.Scheme
		result.Status = utils.ToString(resp.StatusCode)
		result.Language = result.Httpresp.Language
		result.Midware = result.Httpresp.Server
		result.Title = result.Httpresp.Title
	}
	result.AddExtracts(Extractors.Extract(result.Content))
}

//从socket中获取http状态码
func GetStatusCode(content string) (bool, string) {
	if len(content) > 12 && strings.HasPrefix(content, "HTTP") {
		return true, content[9:12]
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
	return utils.SliceUnique(hosts)
}
