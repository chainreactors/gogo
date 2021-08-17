package Utils

import (
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
)

var Compiled = make(map[string][]regexp.Regexp)
var CommonCompiled = initregexp()

func InfoFilter(result *Result) {

	if strings.HasPrefix(result.Protocol, "http") {
		result.Title = GetTitle(result.Content)
		result.Language = GetLanguage(result.Httpresp, result.Content)
		result.Midware = GetMidware(result.Httpresp, result.Content)

	} else {
		result.Title = GetTitle(result.Content)
	}
	//处理错误信息
	if result.Content != "" {
		errHandler(result)
	}

	//return result

}

func GetTitle(content string) string {
	title := CompileMatch(CommonCompiled["title"], content)
	if title != "" {
		return title
	}
	return Encode(string([]byte(content)[:13]))
}

func GetMidware(resp *http.Response, content string) string {
	var server string = ""
	if resp == nil {
		server = CompileMatch(CommonCompiled["server"], content)
	} else {
		server = resp.Header.Get("Server")
	}
	return server
}

// TODO 重构
func GetLanguage(resp *http.Response, content string) string {
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

//从错误中收集信息
func errHandler(result *Result) {

	if strings.Contains(result.Error, "wsasend") || strings.Contains(result.Error, "wsarecv") {
		result.HttpStat = "reset"
	} else if result.Error == "EOF" {
		result.HttpStat = "EOF"
	} else if strings.Contains(result.Error, "http: server gave HTTP response to HTTPS client") {
		result.Protocol = "http"
	} else if strings.Contains(result.Error, "first record does not look like a TLS handshake") {
		result.Protocol = "tcp"
	}
}

func compile(s string) regexp.Regexp {
	reg, err := regexp.Compile(s)
	if err != nil {
		fmt.Println("[-] regexp string error: " + s)
		os.Exit(0)
	}
	return *reg
}

func initregexp() map[string]regexp.Regexp {
	comp := make(map[string]regexp.Regexp)
	comp["title"] = compile("(?Uis)<title>(.*)</title>")
	comp["server"] = compile("(?i)Server: ([\x20-\x7e]+)")
	comp["xpb"] = compile("(?i)X-Powered-By: ([\x20-\x7e]+)")
	comp["sessionid"] = compile("(?i) (.*SESS.*?ID)")
	return comp
}
