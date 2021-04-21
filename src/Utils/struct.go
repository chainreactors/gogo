package Utils

import (
	"net"
	"net/http"
)

type Result struct {
	Ip        string         `json:"ip"`
	Port      string         `json:"port"`
	Stat      string         `json:"-"`
	TcpCon    *net.Conn      `json:"-"`
	Httpresp  *http.Response `json:"-"`
	Os        string         `json:"os"`
	Host      string         `json:"host"`
	Title     string         `json:"title"`
	Midware   string         `json:"midware"`
	HttpStat  string         `json:"http_stat"`
	Language  string         `json:"language"`
	Framework string         `json:"framework"`
	Vuln      string         `json:"vuln"`
	Protocol  string         `json:"protocol"`
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
