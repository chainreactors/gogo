package utils

import (
	"net/http"
	"strings"
)

func getTitle(content string) string {
	title := CompileMatch(CommonCompiled["title"], content)
	if title != "" {
		return title
	}
	return Encode(string([]byte(content)[:13]))
}

func getMidware(resp *http.Response, content string) string {
	var server string = ""
	if resp == nil {
		server = CompileMatch(CommonCompiled["server"], content)
	} else {
		server = resp.Header.Get("Server")
	}
	return server
}

// TODO 重构
func getLanguage(resp *http.Response, content string) string {
	var powered string
	if resp == nil {
		powered = CompileMatch(CommonCompiled["xpb"], content)
		if powered != "" {
			return powered
		}

		sessionid := CompileMatch(CommonCompiled["sessionid"], content)

		if sessionid != "" {
			switch sessionid {
			case "JSESSIONID":
				return "JAVA"
			case "ASP.NET_SessionId":
				return "ASP.NET"
			case "PHPSESSID":
				return "PHP"
			}
		}
	} else {
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

	return ""
}

func getCookies(resp *http.Response) map[string]string {
	cookies := make(map[string]string)
	for _, cookie := range resp.Cookies() {
		cookies[cookie.Name] = cookie.Value
	}
	return cookies
}

//从socket中获取htt状态码
func GetStatusCode(content string) (bool, string) {
	if len(content) > 12 && strings.Contains(content, "HTTP") {
		return true, content[9:12]
	}
	return false, "tcp"
}

func FilterCertDomain(domins []string) string {
	var res string
	if len(domins) == 0 {
		return ""
	} else if len(domins) == 1 {
		return domins[0]
	}
	for _, domain := range domins {
		if !strings.Contains(domain, "www.") {
			res += domain + ","
		}
	}
	return res[:len(res)-1]
}
