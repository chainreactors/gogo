package pkg

import (
	"fmt"
	"github.com/chainreactors/fingers/common"
	"github.com/chainreactors/fingers/fingers"
	"github.com/chainreactors/parsers"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/chainreactors/utils/iutils"
)

func NewResult(ip, port string) *Result {
	result := &Result{
		GOGOResult: parsers.NewGOGOResult(ip, port),
	}
	return result
}

type Result struct {
	*parsers.GOGOResult
	HttpHosts   []string `json:"-"`
	CurrentHost string   `json:"-"`

	IsHttp     bool              `json:"-"`
	Filtered   bool              `json:"-"`
	Open       bool              `json:"-"`
	SmartProbe bool              `json:"-"`
	TcpConn    *net.Conn         `json:"-"`
	HttpConn   *http.Client      `json:"-"`
	Httpresp   *parsers.Response `json:"-"`
	HasTitle   bool              `json:"-"`
	Err        error             `json:"-"`
	Error      string            `json:"-"`
	ErrStat    int               `json:"-"`
	Content    []byte            `json:"-"`
}

func (result *Result) String() string {
	return fmt.Sprintf("%s %s", result.GetBaseURL(), result.Status)
}

func (result *Result) Filter(rules [][]string) bool {
	for _, rule := range rules {
		if len(rule) != 3 {
			continue
		}
		if result.GOGOResult.Filter(rule[0], rule[1], rule[2]) {
			result.Filtered = true
			break
		}
	}
	return result.Filtered
}

func (result *Result) GetHttpConn(delay int) *http.Client {
	if result.HttpConn == nil {
		result.HttpConn = HttpConn(delay)
	} else {
		result.HttpConn.Timeout = time.Duration(delay) * time.Second
	}
	return result.HttpConn
}

func (result *Result) AddVuln(vuln *common.Vuln) {
	result.Vulns[vuln.Name] = vuln
}

func (result *Result) AddVulns(vulns []*common.Vuln) {
	for _, v := range vulns {
		result.AddVuln(v)
	}
}

func (result *Result) AddFramework(f *common.Framework) {
	result.Frameworks.Add(f)
}

func (result *Result) AddFrameworks(fs []*common.Framework) {
	for _, f := range fs {
		result.AddFramework(f)
	}
}

func (result *Result) AddVulnsAndFrameworks(fs common.Frameworks, vs common.Vulns) {
	result.AddFrameworks(fs.List())
	result.AddVulns(vs.List())
}

func (result *Result) AddExtract(extract *parsers.Extracted) {
	if result.Extracteds == nil {
		result.Extracteds = map[string][]string{}
	}
	result.Extracteds[extract.Name] = extract.ExtractResult
}

func (result *Result) AddExtracts(extracts []*parsers.Extracted) {
	for _, extract := range extracts {
		result.AddExtract(extract)
	}
}

func (result *Result) GuessFramework() {
	for _, v := range PresetPorts.PortMap.Get(result.Port) {
		if PresetPorts.TagMap.Get(v) == nil && !iutils.StringsContains([]string{"top1", "top2", "top3", "other", "windows"}, v) {
			result.AddFramework(common.NewFramework(v, common.FrameFromGUESS))
		}
	}
}

func (result *Result) IsHttps() bool {
	if result.Protocol == "https" {
		return true
	}
	return false
}

func (result *Result) ToContent() *fingers.Content {
	if result.IsHttp {
		return fingers.NewContent(result.Content, strings.Join(result.HttpHosts, ","), true)
	} else {
		return fingers.NewContent(result.Content, "", false)
	}
}

// 从错误中收集信息
func (result *Result) errHandler() {
	if result.Error == "" {
		return
	}
	if strings.Contains(result.Error, "wsasend") || strings.Contains(result.Error, "wsarecv") {
		result.Status = "reset"
	} else if result.Error == "EOF" {
		result.Status = "EOF"
	} else if strings.Contains(result.Error, "http: server gave HTTP response to HTTPS client") {
		result.Protocol = "http"
	} else if strings.Contains(result.Error, "first record does not look like a TLS handshake") {
		result.Protocol = "tcp"
	}
}

func (result *Result) GetHostBaseURL() string {
	if result.CurrentHost == "" {
		return result.GetBaseURL()
	} else {
		return fmt.Sprintf("%s://%s:%s", result.Protocol, result.CurrentHost, result.Port)
	}
}

func (result *Result) GetHostURL() string {
	return result.GetHostBaseURL() + result.Uri
}

func (result *Result) AddNTLMInfo(m map[string]string, t string) {
	if m == nil {
		return
	}
	result.Title = m["MsvAvNbDomainName"] + "/" + m["MsvAvNbComputerName"]
	result.Host = strings.Trim(m["MsvAvDnsDomainName"], "\x00") + "/" + m["MsvAvDnsComputerName"]
	result.AddFramework(common.NewFrameworkWithVersion(t, common.FrameFromDefault, m["Version"]))
}
