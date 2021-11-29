package utils

import (
	"fmt"
	"getitle/src/structutils"
	"net"
	"net/http"
	"strings"
)

type Result struct {
	Ip         string         `json:"i"` // ip
	Port       string         `json:"p"` // port
	Uri        string         `json:"u"` // uri
	Os         string         `json:"o"` // os
	Host       string         `json:"h"` // host
	Title      string         `json:"t"` // title
	Midware    string         `json:"m"` // midware
	HttpStat   string         `json:"s"` // http_stat
	Language   string         `json:"l"` // language
	Frameworks Frameworks     `json:"f"` // framework
	Protocol   string         `json:"r"` // protocol
	Hash       string         `json:"hs"`
	Vulns      Vulns          `json:"v"`
	Open       bool           `json:"-"`
	TcpCon     *net.Conn      `json:"-"`
	Httpresp   *http.Response `json:"-"`
	Error      string         `json:"-"`
	Content    string         `json:"-"`
}

func (result *Result) InfoFilter() {
	//result.errHandler()
	result.Title = getTitle(result.Content)
	if result.Content != "" {
		result.Hash = structutils.Md5Hash([]byte(result.Content))[:4]
	}
	if result.IsHttp() {
		result.Language = getLanguage(result.Httpresp, result.Content)
		result.Midware = getMidware(result.Httpresp, result.Content)
	}
}

func (result *Result) AddVuln(vuln Vuln) {
	result.Vulns = append(result.Vulns, vuln)
}

func (result *Result) AddVulns(vulns []Vuln) {
	result.Vulns = append(result.Vulns, vulns...)
}

func (result *Result) AddFramework(f Framework) {
	result.Frameworks = append(result.Frameworks, f)
}

func (result *Result) NoFramework() bool {
	if len(result.Frameworks) == 0 {
		return true
	}
	return false
}

func (result *Result) GuessFramework() {
	for _, v := range Portmap[result.Port] {
		if Tagmap[v] == nil && !structutils.SliceContains([]string{"top1", "top2", "top3", "other", "windows"}, v) {
			result.AddFramework(Framework{Name: v, IsGuess: true})
		}
	}
}

func (result Result) IsHttp() bool {
	if strings.HasPrefix(result.Protocol, "http") {
		return true
	}
	return false
}

func (result Result) IsHttps() bool {
	if strings.HasPrefix(result.Protocol, "https") {
		return true
	}
	return false
}

//从错误中收集信息
func (result *Result) errHandler() {
	if result.Error == "" {
		return
	}
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

func (result *Result) GetURL() string {
	return fmt.Sprintf("%s://%s:%s", result.Protocol, result.Ip, result.Port)
}

func (result *Result) GetTarget() string {
	return fmt.Sprintf("%s:%s", result.Ip, result.Port)
}

func (result *Result) AddNTLMInfo(m map[string]string, t string) {
	result.Title = m["MsvAvNbDomainName"] + "/" + m["MsvAvNbComputerName"]
	result.Host = m["MsvAvDnsDomainName"] + "/" + m["MsvAvDnsComputerName"]
	result.AddFramework(Framework{Name: t, Version: m["Version"]})
}

type Vuln struct {
	Name    string                 `json:"vn"`
	Payload map[string]interface{} `json:"vp"`
	Detail  map[string]interface{} `json:"vd"`
}

func (v *Vuln) GetPayload() string {
	return structutils.MaptoString(v.Payload)
}

func (v *Vuln) GetDetail() string {
	return structutils.MaptoString(v.Detail)
}

func (v *Vuln) ToString() string {
	s := v.Name
	if payload := v.GetPayload(); payload != "" {
		s += fmt.Sprintf(" payloads:%s", payload)
	}
	if detail := v.GetDetail(); detail != "" {
		s += fmt.Sprintf(" payloads:%s", detail)
	}
	return s
}

type Vulns []Vuln

func (vs Vulns) ToString() string {
	var s string
	for _, vuln := range vs {
		s += fmt.Sprintf("[ Find Vuln: %s ] ", vuln.ToString())
	}
	return s
}

type Framework struct {
	Name    string `json:"ft"`
	Version string `json:"fv"`
	IsGuess bool   `json:"fg"`
}

func (f Framework) ToString() string {
	if f.IsGuess {
		return fmt.Sprintf("*%s", f.Name)
	} else {
		if f.Version == "" {
			return fmt.Sprintf("%s", f.Name)
		} else {
			return fmt.Sprintf("%s:%s", f.Name, f.Version)
		}
	}

}

type Frameworks []Framework

func (fs Frameworks) ToString() string {
	framework_strs := make([]string, len(fs))
	for i, f := range fs {
		framework_strs[i] = f.ToString()
	}
	return strings.Join(framework_strs, "||")
}

func (fs Frameworks) GetTitles() []string {
	var titles []string
	//titles := []string{}
	for _, f := range fs {
		if !f.IsGuess {
			titles = append(titles, f.Name)
		}
	}
	return titles
}
