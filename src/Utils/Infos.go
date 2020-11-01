package Utils

import (
	"fmt"
	"io/ioutil"
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

//发送内容
func InfoFilter(content string, result Result) Result {

	result.Title = GetTitle(content)
	result.Midware = GetMidware(content)
	result.Language = GetLanguage(content)
	result.Framework = GetFrameWork(content)

	return result

}

func Encode(s string) string {
	s = strings.Replace(s, "\r", "%13", -1)
	s = strings.Replace(s, "\n", "%10", -1)
	return s
}

func Match(Regexp string, s string) string {
	Reg, _ := regexp.Compile(Regexp)
	res := Reg.FindStringSubmatch(s)
	if len(res) >= 2 {
		return string(res[1])
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

func GetFrameWork(content string) string {
	return ""
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

	return "999"
}
