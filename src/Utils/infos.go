package Utils

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
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
	Name        string   `json:"name"`
	Level       int      `json:"level"`
	Defaultport string   `json:"defaultport"`
	Regexps     []string `json:"regexps"`
}

var fingers = getFingers()
var Version bool

func InfoFilter(result Result) Result {
	var ishttp = false
	if strings.HasPrefix(result.Protocol, "http") {
		ishttp = true
	}
	content := result.Content
	result.Title = GetTitle(content)

	if ishttp {
		result.Language = GetLanguage(content)
		result.Midware = GetMidware(content)
	}
	// 因为正则匹配耗时较长,如果没有-v参数则字节不进行服务识别
	if !Version {
		return result
	}

	//如果是http协议,则判断cms,如果是tcp则匹配规则库
	if result.Protocol == "tcp" {
		var title string
		result.Framework, title = GetFrameWork(content, result.Port)
		if title != "" {
			result.Title = title
		}
	} else if ishttp {
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
func GetFrameWork(content string, port string) (version string, title string) {

	// 通过默认端口加快匹配速度
	defaultportFingers, otherportFingers := fingerSplit(port)
	version, title = fingerMatch(content, defaultportFingers)
	if version == "" {
		version, title = fingerMatch(content, otherportFingers)
	}
	return version, title
}

func fingerMatch(content string, tmpfingers []Finger) (string, string) {
	for _, finger := range tmpfingers {
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

func getFingers() []Finger {
	fingersJson := loadFingers()

	var fingers []Finger
	err := json.Unmarshal([]byte(fingersJson), &fingers)
	if err != nil {
		println("[-] fingers load FAIL!")
		os.Exit(0)
	}
	return fingers
}

// 通过默认端口加快匹配速度
func fingerSplit(port string) ([]Finger, []Finger) {
	var defaultportFingers, otherportFingers []Finger
	for _, finger := range fingers {
		if finger.Defaultport == port {
			defaultportFingers = append(defaultportFingers, finger)
		} else {
			otherportFingers = append(otherportFingers, finger)
		}
	}
	return defaultportFingers, otherportFingers
}

func GetCurtime() string {
	h := strconv.Itoa(time.Now().Hour())
	m := strconv.Itoa(time.Now().Minute())
	s := strconv.Itoa(time.Now().Second())

	curtime := h + ":" + m + ":" + s
	return curtime
}
