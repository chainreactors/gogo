package pkg

import (
	"fmt"
	"github.com/chainreactors/gogo/v2/pkg/fingers"
	"github.com/chainreactors/parsers"
	"github.com/chainreactors/parsers/iutils"
	"net"
	"net/http"
	"strings"
	"time"
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

	// language
	IsHttp bool `json:"-"`
	Open   bool `json:"-"`
	//FrameworksMap map[string]bool `json:"-"`
	SmartProbe bool              `json:"-"`
	TcpConn    *net.Conn         `json:"-"`
	HttpConn   *http.Client      `json:"-"`
	Httpresp   *parsers.Response `json:"-"`
	Error      string            `json:"-"`
	ErrStat    int               `json:"-"`
	Content    string            `json:"-"`
}

func (result *Result) GetHttpConn(delay int) *http.Client {
	if result.HttpConn == nil {
		result.HttpConn = HttpConn(delay)
	} else {
		result.HttpConn.Timeout = time.Duration(delay) * time.Second
	}
	return result.HttpConn
}

func (result *Result) AddVuln(vuln *parsers.Vuln) {
	result.Vulns = append(result.Vulns, vuln)
}

func (result *Result) AddVulns(vulns []*parsers.Vuln) {
	for _, v := range vulns {
		result.AddVuln(v)
	}
}

func (result *Result) AddFramework(f *parsers.Framework) {
	result.Frameworks.Add(f)
}

func (result *Result) AddFrameworks(fs []*parsers.Framework) {
	for _, f := range fs {
		result.AddFramework(f)
	}
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
	for _, v := range PortMap.Get(result.Port) {
		if TagMap.Get(v) == nil && !iutils.StringsContains([]string{"top1", "top2", "top3", "other", "windows"}, v) {
			result.AddFramework(&parsers.Framework{Name: v, From: fingers.GUESS})
		}
	}
}

func (result *Result) IsHttps() bool {
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
	result.AddFramework(&parsers.Framework{Name: t, Version: m["Version"]})
}
