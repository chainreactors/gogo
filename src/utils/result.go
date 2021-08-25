package utils

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

type Result struct {
	Ip        string         `json:"i"` // ip
	Port      string         `json:"p"` // port
	Uri       string         `json:"u"` // uri
	Os        string         `json:"o"` // os
	Host      string         `json:"h"` // host
	Title     string         `json:"t"` // title
	Midware   string         `json:"m"` // midware
	HttpStat  string         `json:"s"` // http_stat
	Language  string         `json:"l"` // language
	Framework string         `json:"f"` // framework
	Protocol  string         `json:"r"` // protocol
	Vulns     []Vuln         `json:"vs"`
	Stat      string         `json:"-"`
	TcpCon    *net.Conn      `json:"-"`
	Httpresp  *http.Response `json:"-"`
	Error     string         `json:"-"`
	Content   string         `json:"-"`
}

func (result *Result) InfoFilter() {
	if strings.HasPrefix(result.Protocol, "http") {
		result.Title = getTitle(result.Content)
		result.Language = getLanguage(result.Httpresp, result.Content)
		result.Midware = getMidware(result.Httpresp, result.Content)

	} else {
		result.Title = getTitle(result.Content)
	}
	//处理错误信息
	if result.Content != "" {
		result.errHandler()
	}
}

func (result *Result) AddVuln(vuln Vuln) {
	result.Vulns = append(result.Vulns, vuln)
}

//从错误中收集信息
func (result *Result) errHandler() {

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

func (result Result) GetURL() string {
	return fmt.Sprintf("%s://%s:%s", result.Protocol, result.Ip, result.Port)
}

type Vuln struct {
	Id      string                 `json:"v"`
	Payload map[string]interface{} `json:"vp"`
	Detail  map[string]interface{} `json:"vd"`
}

func (v *Vuln) GetPayload() string {
	return MaptoString(v.Payload)
}

func (v *Vuln) GetDetail() string {
	return MaptoString(v.Detail)
}

func (v *Vuln) ToString() string {
	s := v.Id
	if payload := v.GetPayload(); payload != "" {
		s += fmt.Sprintf(" payloads: %s", payload)
	}
	if detail := v.GetDetail(); detail != "" {
		s += fmt.Sprintf(" payloads: %s", detail)
	}
	return s
}
