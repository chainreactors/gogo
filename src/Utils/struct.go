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

type Request struct {
	// Operators for the current request go here.
	// Path contains the path/s for the request
	Path []string `json:"path"`
	// Raw contains raw requests
	Raw []string `json:"raw"`
	ID  string   `json:"id"`
	// Name is the name of the request
	Name string `json:"Name"`
	// AttackType is the attack type
	// Sniper, PitchFork and ClusterBomb. Default is Sniper
	AttackType string `json:"attack"`
	// Method is the request method, whether GET, POST, PUT, etc
	Method string `json:"method"`
	// Body is an optional parameter which contains the request body for POST methods, etc
	Body string `json:"body"`
	// Path contains the path/s for the request variables
	Payloads map[string]interface{} `json:"payloads"`
	// Headers contains headers to send with the request
	Headers map[string]string `json:"headers"`
	// RaceNumberRequests is the number of same request to send in race condition attack
	RaceNumberRequests int `json:"race_count"`
	// MaxRedirects is the maximum number of redirects that should be followed.
	MaxRedirects int `json:"max-redirects"`
	// PipelineConcurrentConnections is number of connections in pipelining
	Threads int `json:"threads"`

	// MaxSize is the maximum size of http response body to read in bytes.
	MaxSize int `json:"max-size"`

	// CookieReuse is an optional setting that makes cookies shared within requests
	CookieReuse bool `json:"cookie-reuse"`
	// Redirects specifies whether redirects should be followed.
	Redirects bool `json:"redirects"`
	// Pipeline defines if the attack should be performed with HTTP 1.1 Pipelining (race conditions/billions requests)
	// All requests must be indempotent (GET/POST)
	Unsafe bool `json:"unsafe"`
	// Race determines if all the request have to be attempted at the same time
	// The minimum number of requests is determined by threads
	Race bool `json:"race"`
	// ReqCondition automatically assigns numbers to requests and preserves
	// their history for being matched at the end.
	// Currently only works with sequential http requests.
	ReqCondition bool `json:"req-condition"`
}

type Matcher struct {
	// Type is the type of the matcher
	Type string `json:"type"`
	// Condition is the optional condition between two matcher variables
	//
	// By default, the condition is assumed to be OR.
	Condition string `json:"condition,omitempty"`

	// Part is the part of the data to match
	Part string `json:"part,omitempty"`

	// Negative specifies if the match should be reversed
	// It will only match if the condition is not true.
	Negative bool `json:"negative,omitempty"`

	// Name is matcher Name
	Name string `json:"name,omitempty"`
	// Status are the acceptable status codes for the response
	Status []int `json:"status,omitempty"`
	// Size is the acceptable size for the response
	Size []int `json:"size,omitempty"`
	// Words are the words required to be present in the response
	Words []string `json:"words,omitempty"`
	// Regex are the regex pattern required to be present in the response
	Regex []string `json:"regex,omitempty"`
	// Binary are the binary characters required to be present in the response
	Binary []string `json:"binary,omitempty"`
	// DSL are the dsl queries
	DSL []string `json:"dsl,omitempty"`
	// Encoding specifies the encoding for the word content if any.
	Encoding string `json:"encoding,omitempty"`

	MatchersCondition string    `json:"matchers-condition"`
	Matchers          []Matcher `json:"matchers"`
}

type Template struct {
	Id   string `json:"id"`
	Info struct {
		Name      string `json:"name"`
		Author    string `json:"author"`
		Severity  string `json:"severity"`
		Reference string `json:"reference"`
		Vendor    string `json:"vendor"`
		Tags      string `json:"tags"`
	} `json:"info"`
	Requests []Request `json:"requests"`
}

type T struct {
	Id   string `json:"id"`
	Info struct {
		Name      string `json:"name"`
		Author    string `json:"author"`
		Severity  string `json:"severity"`
		Reference string `json:"reference"`
		Vendor    string `json:"vendor"`
		Tags      string `json:"tags"`
	} `json:"info"`
	Requests []struct {
		Raw               []string `json:"raw"`
		MatchersCondition string   `json:"matchers-condition"`
		Matchers          []struct {
			Type   string   `json:"type"`
			Regex  []string `json:"regex,omitempty"`
			Part   string   `json:"part,omitempty"`
			Status []int    `json:"status,omitempty"`
		} `json:"matchers"`
	} `json:"requests"`
}
