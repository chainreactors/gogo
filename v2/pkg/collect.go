package pkg

import (
	//"github.com/chainreactors/gogo/pkg/dsl"
	utils2 "github.com/chainreactors/gogo/v2/pkg/utils"
	"net/http"
	"strings"
)

func CollectSocketInfo(result *Result, socketContent []byte) {
	content := string(socketContent)
	ishttp, statuscode := GetStatusCode(content)
	if ishttp {
		//var body string
		//bodyIndex := strings.Index(content, "\r\n\r\n")
		//if bodyIndex != -1 {
		//	body = content[bodyIndex:]
		//}

		result.HttpStat = statuscode
		result.Protocol = "http"
		//result.Hash = dsl.Md5Hash([]byte(strings.TrimSpace(body)))[:4] // 因为头中经常有随机值, 因此hash通过body判断
		result.Language = getSocketLanguage(content)
		result.Midware, _ = CompiledMatch(CommonCompiled["server"], content)
	}
	result.Title = GetTitle(content)
	result.AddExtracts(ExtractContent(content))
}

func CollectHttpInfo(result *Result, resp *http.Response, content string) {
	result.Httpresp = resp
	//cs := strings.Index(content, "\r\n\r\n")
	//var body string
	//if cs != -1 {
	//	body = content[cs+4:]
	//} else {
	//	body = ""
	//}
	//result.Content = content
	if resp != nil {
		result.Protocol = resp.Request.URL.Scheme
		result.HttpStat = utils2.ToString(resp.StatusCode)
		result.Language = getHttpLanguage(resp)
		result.Midware = resp.Header.Get("Server")
	}

	result.Title = GetTitle(content)
	//if body != "" {
	//	result.Hash = dsl.Md5Hash([]byte(strings.TrimSpace(body)))[:4] // 因为头中经常有随机值, 因此hash通过body判断
	//} else {
	//	result.Hash = "0000"
	//}
	result.AddExtracts(ExtractContent(content))
}

func GetTitle(content string) string {
	if content == "" {
		return ""
	}
	title, ok := CompiledMatch(CommonCompiled["title"], content)
	if ok {
		return title
	} else if len(content) > 13 {
		return content[0:13]
	} else {
		return content
	}
}

func ExtractContent(content string) []*Extracted {
	var extracts []*Extracted
	if content != "" {
		for name, extract := range Extractors {
			extractStr, ok := CompiledAllMatch(extract, content)
			if ok && extractStr != nil {
				extracts = append(extracts, NewExtracted(name, extractStr))
			}
		}
	}
	return extracts
}

// TODO 重构
func getHttpLanguage(resp *http.Response) string {
	var powered string
	powered = resp.Header.Get("X-Powered-By")
	if powered != "" {
		return powered
	}

	cookies := getCookies(resp)
	if cookies["JSESSIONID"] != "" {
		return "JAVA"
	} else if cookies["ASP.NET_SessionId"] != "" {
		return "ASP"
	} else if cookies["PHPSESSID"] != "" {
		return "PHP"
	} else {
		return ""
	}
}

func getSocketLanguage(content string) string {
	powered, ok := CompiledMatch(CommonCompiled["xpb"], content)
	if ok {
		return powered
	}

	sessionid, ok := CompiledMatch(CommonCompiled["sessionid"], content)
	if ok {
		switch sessionid {
		case "JSESSIONID":
			return "JAVA"
		case "ASP.NET_SessionId":
			return "ASP.NET"
		case "PHPSESSID":
			return "PHP"
		}
	}
	return ""
}

func getCookies(resp *http.Response) map[string]string {
	cookies := make(map[string]string)
	for _, cookie := range resp.Cookies() {
		cookies[cookie.Name] = cookie.Value
	}
	return cookies
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
	return utils2.SliceUnique(hosts)
}
