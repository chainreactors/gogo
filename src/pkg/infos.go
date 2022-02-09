package pkg

import (
	"net"
	"net/http"
	"sort"
	"strings"
)

func getTitle(content string) string {
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

func getMidware(resp *http.Response, content string) string {
	var server string
	if resp == nil {
		server, _ = CompiledMatch(CommonCompiled["server"], content)
	} else {
		server = resp.Header.Get("Server")
	}
	return server
}

// TODO 重构
func getLanguage(resp *http.Response, content string) string {
	var powered string
	if resp == nil {
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
	if len(content) > 12 && strings.HasPrefix(content, "HTTP") {
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

func ip2int(ip string) uint {
	s2ip := net.ParseIP(ip).To4()
	return uint(s2ip[3]) | uint(s2ip[2])<<8 | uint(s2ip[1])<<16 | uint(s2ip[0])<<24
}

func int2ip(ipint uint) string {
	ip := make(net.IP, net.IPv4len)
	ip[0] = byte(ipint >> 24)
	ip[1] = byte(ipint >> 16)
	ip[2] = byte(ipint >> 8)
	ip[3] = byte(ipint)
	return ip.String()
}

func sortIP(ips []string) []string {
	sort.Slice(ips, func(i, j int) bool {
		return ip2int(ips[i]) < ip2int(ips[j])
	})
	return ips
}
