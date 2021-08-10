package Utils

import (
	"net"
	"net/http"
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
	Vuln      string         `json:"v"` // vuln
	Protocol  string         `json:"r"` // protocol
	Stat      string         `json:"-"`
	TcpCon    *net.Conn      `json:"-"`
	Httpresp  *http.Response `json:"-"`
	Error     string         `json:"-"`
	Content   string         `json:"-"`
}

type Finger struct {
	Name        string   `json:"name"`
	Protocol    string   `json:"protocol"`
	SendData    string   `json:"send_data"`
	Vuln        string   `json:"vuln"`
	Level       int      `json:"level"`
	Defaultport []string `json:"default_port"`
	Regexps     Regexps  `json:"regexps"`
}

type Regexps struct {
	HTML   []string `json:"html"`
	MD5    []string `json:"md5"`
	Regexp []string `json:"regexp"`
	Cookie []string `json:"cookie"`
	Header []string `json:"header"`
	Vuln   []string `json:"vuln"`
}

type PortFinger struct {
	Name  string   `json:"name"`
	Ports []string `json:"ports"`
	Type  []string `json:"type"`
}
