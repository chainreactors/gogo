package Utils

import (
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"regexp"
	"strings"
)

type Result struct {
	Ip        string
	Port      string
	Stat      string
	Os        string
	Host      string
	Title     string
	Midware   string
	HttpStat  string
	Language  string
	Framework string
	Vuln      string
	Protocol  string
	Error     string
	Content   string
}

type Finger struct {
	Name    string   `json:"name"`
	Level   int      `json:"level"`
	Regexps []string `json:"regexps"`
}

var fingers = GetFinger()
var Version bool

func InfoFilter(content string, result Result) Result {

	result.Title = GetTitle(content)
	result.Midware = GetMidware(content)
	result.Language = GetLanguage(content)

	// 因为正则匹配耗时较长,如果没有-v参数则字节不进行服务识别
	if !Version {
		return result
	}

	//如果是http协议,则判断cms,如果是tcp则匹配规则库
	if result.HttpStat == "tcp" {
		var title string
		result.Framework, title = GetFrameWork(content)
		if title != "" {
			result.Title = title
		}
	} else {
		result.Framework = GetHttpCMS(content)
	}

	return result

}

func Encode(s string) string {
	s = strings.Replace(s, "\r", "%13", -1)
	s = strings.Replace(s, "\n", "%10", -1)
	return s
}

func Match(regexpstr string, s string) string {
	Reg, err := regexp.Compile(regexpstr)
	if err != nil {
		return ""
	}
	res := Reg.FindStringSubmatch(s)
	if len(res) == 1 {
		return "matched"
	} else if len(res) == 2 {
		return res[1]
	}
	return ""
}

func GetTitle(content string) string {
	title := Match("(?im)<title>(.*)</title>", content)
	if title != "" {
		return title
	}
	return Encode(string([]byte(content)[:13]))
}

func GetMidware(content string) string {

	server := Match("(?i)Server: ([\x20-\x7e]+)", strings.Split(content, "\r\n\r\n")[0])
	if server != "" {
		return server
	}

	return ""

}

func GetLanguage(content string) string {

	powered := Match("(?i)X-Powered-By: ([\x20-\x7e]+)", strings.Split(content, "\r\n\r\n")[0])

	if powered != "" {
		return powered
	}

	sessionid := Match("(?i) (.*SESS.*?ID)", content)

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

	return ""
}

func GetHttpCMS(content string) string {
	return ""
}

//第一个返回值为详细的版本信息,第二个返回值为规则名字
func GetFrameWork(content string) (string, string) {
	// 遍历框架
	for _, finger := range fingers {
		//遍历正则
		for _, regexpstr := range finger.Regexps {
			regexpstr = regexpstr
			res := Match("(?im)"+regexpstr, content)
			if res == "matched" {
				//println("[*] " + res)
				return finger.Name, finger.Name
			} else if res != "" {
				return res, finger.Name
			}
		}
	}
	return "", ""
}

func GetHttpRaw(resp http.Response) string {
	var raw string

	raw += fmt.Sprintf("%s %s\r\n", resp.Proto, resp.Status)
	for k, v := range resp.Header {
		for _, i := range v {
			raw += fmt.Sprintf("%s: %s\r\n", k, i)
		}
	}
	raw += "\r\n"
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return raw
	}
	raw += string(body)
	return raw
}

func GetStatusCode(content string) string {
	if strings.Contains(content, "HTTP") {
		return content[9:12]
	}

	return "tcp"
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

func isIPv4(ip string) bool {
	address := net.ParseIP(ip)
	if address != nil {
		return true
	}
	return false
}

func GetIp(target string) string {
	if isIPv4(target) {
		return target
	}
	iprecords, _ := net.LookupIP(target)
	for _, ip := range iprecords {
		if isIPv4(ip.String()) {
			println("[*] parse domin SUCCESS, map " + target + " to " + ip.String())
			return ip.String()
		}
	}
	return ""
}
