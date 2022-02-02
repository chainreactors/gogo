package utils

import (
	"encoding/json"
	"fmt"
	"getitle/src/structutils"
	"net"
	"net/http"
	"strconv"
	"strings"
)

type Result struct {
	Ip           string         `json:"i"` // ip
	Port         string         `json:"p"` // port
	Uri          string         `json:"u"` // uri
	Os           string         `json:"o"` // os
	Host         string         `json:"h"` // host
	Title        string         `json:"t"` // title
	Midware      string         `json:"m"` // midware
	HttpStat     string         `json:"s"` // http_stat
	Language     string         `json:"l"` // language
	Frameworks   Frameworks     `json:"f"` // framework
	Vulns        Vulns          `json:"v"`
	Extracts     *Extracts      `json:"-"`
	ExtractsStat map[string]int `json:"ec"`
	Protocol     string         `json:"r"` // protocol
	Hash         string         `json:"hs"`
	Open         bool           `json:"-"`
	SmartProbe   bool           `json:"-"`
	TcpCon       *net.Conn      `json:"-"`
	Httpresp     *http.Response `json:"-"`
	Error        string         `json:"-"`
	ErrStat      int            `json:"-"`
	Content      string         `json:"-"`
}

func NewResult(ip, port string) *Result {
	var result = Result{
		Ip:           ip,
		Port:         port,
		Protocol:     "tcp",
		HttpStat:     "tcp",
		Extracts:     &Extracts{},
		ExtractsStat: map[string]int{},
	}
	result.Extracts.Target = result.GetTarget()
	return &result
}
func (result *Result) InfoFilter() {
	//result.errHandler()
	result.Title = getTitle(result.Content)
	if result.Content != "" {
		result.Hash = Md5Hash([]byte(result.Content))[:4]
		for name, extract := range Extractors {
			extractStr, ok := CompiledAllMatch(extract, result.Content)
			if ok && extractStr != nil {
				result.AddExtract(NewExtract(name, extractStr))
			}
		}
	}
	if result.IsHttp() {
		result.Language = getLanguage(result.Httpresp, result.Content)
		result.Midware = getMidware(result.Httpresp, result.Content)
	}
}

func (result *Result) AddVuln(vuln *Vuln) {
	result.Vulns = append(result.Vulns, vuln)
}

func (result *Result) AddVulns(vulns []*Vuln) {
	result.Vulns = append(result.Vulns, vulns...)
}

func (result *Result) AddFramework(f *Framework) {
	result.Frameworks = append(result.Frameworks, f)
}

func (result *Result) AddFrameworks(f []*Framework) {
	result.Frameworks = append(result.Frameworks, f...)
}

func (result *Result) AddExtract(extract *Extract) {
	result.Extracts.Extracts = append(result.Extracts.Extracts, extract)
	result.ExtractsStat[extract.Name] = len(extract.ExtractResult)
}

func (result *Result) GetExtractStat() string {
	if len(result.ExtractsStat) > 0 {
		var s []string
		for name, length := range result.ExtractsStat {
			s = append(s, fmt.Sprintf("%s:%ditems", name, length))
		}
		return fmt.Sprintf("[ extracts: %s ]", strings.Join(s, ", "))
	} else {
		return ""
	}
}

func (result Result) NoFramework() bool {
	if len(result.Frameworks) == 0 {
		return true
	}
	return false
}

func (result *Result) GuessFramework() {
	for _, v := range PortMap[result.Port] {
		if TagMap[v] == nil && !structutils.SliceContains([]string{"top1", "top2", "top3", "other", "windows"}, v) {
			result.AddFramework(&Framework{Name: v, IsGuess: true})
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

func (result Result) Get(key string) string {
	switch key {
	case "ip":
		return result.Ip
	case "port":
		return result.Port
	case "frameworks":
		return result.Frameworks.ToString()
	case "vulns":
		return result.Vulns.ToString()
	case "host":
		return result.Host
	case "title":
		return result.Title
	case "target":
		return result.GetTarget()
	case "url":
		return result.GetURL()
	default:
		return ""
	}
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

func (result Result) GetURL() string {
	return fmt.Sprintf("%s://%s:%s", result.Protocol, result.Ip, result.Port)
}

func (result Result) GetTarget() string {
	return fmt.Sprintf("%s:%s", result.Ip, result.Port)
}

func (result Result) GetFirstFramework() string {
	if !result.NoFramework() {
		return result.Frameworks[0].Name
	}
	return ""
}

func (result *Result) AddNTLMInfo(m map[string]string, t string) {
	result.Title = m["MsvAvNbDomainName"] + "/" + m["MsvAvNbComputerName"]
	result.Host = m["MsvAvDnsDomainName"] + "/" + m["MsvAvDnsComputerName"]
	result.AddFramework(&Framework{Name: t, Version: m["Version"]})
}

func (result Result) toZombie() zombiemeta {
	port, _ := strconv.Atoi(result.Port)
	return zombiemeta{
		IP:     result.Ip,
		Port:   port,
		Server: zombiemap[strings.ToLower(result.GetFirstFramework())],
	}
}

func (result Result) Filter(k, v, op string) bool {
	var matchfunc func(string, string) bool
	if op == "::" {
		matchfunc = strings.Contains
	} else {
		matchfunc = strings.EqualFold
	}

	if matchfunc(strings.ToLower(result.Get(k)), v) {
		return true
	}
	return false
}

type zombiemeta struct {
	IP     string `json:"IP"`
	Port   int    `json:"Port"`
	Server string `json:"Server"`
}

type Results []*Result

func (rs Results) Filter(k, v, op string) Results {
	var filtedres Results

	for _, result := range rs {
		if result.Filter(k, v, op) {
			filtedres = append(filtedres, result)
		}
	}
	return filtedres
}

func (results Results) GetValues(key string) []string {
	values := make([]string, len(results))
	for i, result := range results {
		values[i] = result.Get(key)
	}
	return values
}

const (
	// info leak
	Info int = iota + 1
	Low
	Medium
	High
	Critical
)

var serverityMap = map[string]int{
	"info":     Info,
	"low":      Low,
	"medium":   Medium,
	"high":     High,
	"critical": Critical,
}

type Vuln struct {
	Name     string                 `json:"vn"`
	Payload  map[string]interface{} `json:"vp"`
	Detail   map[string]interface{} `json:"vd"`
	Severity string                 `json:"vs"`
}

func (v *Vuln) GetPayload() string {
	return structutils.MaptoString(v.Payload)
}

func (v *Vuln) GetDetail() string {
	return structutils.MaptoString(v.Detail)
}

func (v *Vuln) GetLevel() int {
	if level, ok := serverityMap[v.Severity]; ok && v.Severity != "" {
		return level
	} else {
		// 漏洞默认危害为high
		return 3
	}
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

type Vulns []*Vuln

func (vs Vulns) ToString() string {
	var s string
	for _, vuln := range vs {
		if vuln.GetLevel() <= 1 {
			s += fmt.Sprintf("[ Info: %s ] ", vuln.ToString())
		} else {
			s += fmt.Sprintf("[ Vuln: %s ] ", vuln.ToString())
		}
	}
	return s
}

type Framework struct {
	Name    string `json:"ft"`
	Version string `json:"fv"`
	IsGuess bool   `json:"fg"`
}

func (f Framework) ToString() string {
	var s = f.Name
	if f.IsGuess {
		s = "*" + s
	}
	if f.Version != "" {
		s += ":" + f.Version
	}
	return s
}

type Frameworks []*Framework

func (fs Frameworks) ToString() string {
	frameworkStrs := make([]string, len(fs))
	for i, f := range fs {
		frameworkStrs[i] = f.ToString()
	}
	return strings.Join(frameworkStrs, "||")
}

func (fs Frameworks) GetTitles() []string {
	var titles []string
	for _, f := range fs {
		if !f.IsGuess {
			titles = append(titles, f.Name)
		}
	}
	return titles
}

type Extract struct {
	Name          string   `json:"name"`
	ExtractResult []string `json:"extract_result"`
}

func (e *Extract) ToString() string {
	if len(e.ExtractResult) == 1 {
		if len(e.ExtractResult[0]) > 30 {
			return fmt.Sprintf("%s:%s ... %d bytes", e.Name, AsciiEncode(e.ExtractResult[0][:30]), len(e.ExtractResult[0]))
		}
		return fmt.Sprintf("%s:%s", e.Name, AsciiEncode(e.ExtractResult[0]))
	} else {
		return fmt.Sprintf("%s:%d items", e.Name, len(e.ExtractResult))
	}
}

func NewExtract(name string, extractResult interface{}) *Extract {
	var e = &Extract{
		Name: name,
	}
	switch extractResult.(type) {
	case string:
		e.ExtractResult = append(e.ExtractResult, extractResult.(string))
	case []byte:
		e.ExtractResult = append(e.ExtractResult, string(extractResult.([]byte)))
	case []string:
		e.ExtractResult = append(e.ExtractResult, extractResult.([]string)...)
	}
	return e
}

type Extracts struct {
	Target       string     `json:"target"`
	MatchedNames []string   `json:"-"`
	Extracts     []*Extract `json:"extracts"`
}

func (e *Extracts) ToResult() string {
	s, err := json.Marshal(e)
	if err != nil {
		return err.Error()
	}
	return string(s)
}

func (es Extracts) ToString() string {
	var s string
	for _, e := range es.Extracts {
		s += fmt.Sprintf("[ Extract: %s ] ", e.ToString())
	}
	return s
}
