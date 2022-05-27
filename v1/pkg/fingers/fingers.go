package fingers

import (
	b64 "encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
)

// common struct
func decode(s string) []byte {
	var bs []byte
	if s[:4] == "b64|" {
		bs, _ = b64.StdEncoding.DecodeString(s[4:])
	} else {
		bs = []byte(s)
	}
	return bs
}

func compileRegexp(s string) (*regexp.Regexp, error) {
	reg, err := regexp.Compile(s)
	if err != nil {
		return nil, err
	}
	return reg, nil
}

func maptoString(m map[string]interface{}) string {
	if m == nil || len(m) == 0 {
		return ""
	}
	var s string
	for k, v := range m {
		s += fmt.Sprintf(" %s:%s ", k, v.(string))
	}
	return s
}

type Finger struct {
	Name        string   `json:"name"`
	Protocol    string   `json:"protocol"`
	SendDataStr string   `json:"send_data"`
	SendData    senddata `json:"-"`
	Info        string   `json:"info"`
	Vuln        string   `json:"vuln"`
	Level       int      `json:"level"`
	Defaultport []string `json:"default_port"`
	Regexps     Regexps  `json:"regexps"`
}

func (f *Finger) Compile(portHandler func([]string) []string) error {
	if f.Protocol == "" {
		f.Protocol = "http"
	}

	if len(f.Defaultport) == 0 {
		if f.Protocol == "http" {
			f.Defaultport = []string{"80"}
		}
	} else {
		f.Defaultport = portHandler(f.Defaultport)
	}

	f.Decode()

	for _, reg := range f.Regexps.Regexp {
		creg, err := compileRegexp(reg)
		if err != nil {
			return err
		}
		f.Regexps.CompliedRegexp = append(f.Regexps.CompliedRegexp, creg)
	}

	for _, reg := range f.Regexps.Vuln {
		creg, err := compileRegexp(reg)
		if err != nil {
			return err
		}
		f.Regexps.CompiledVulnRegexp = append(f.Regexps.CompiledVulnRegexp, creg)
	}
	return nil
}

func (f *Finger) Decode() {
	if f.Protocol != "tcp" {
		return
	}

	if f.SendDataStr != "" {
		f.SendData = decode(f.SendDataStr)
	}
	// todo
	// regexp decode
}

type senddata []byte

func (d senddata) IsNull() bool {
	if len(d) == 0 {
		return true
	}
	return false
}

type Regexps struct {
	Body               []string `json:"body"`
	MD5                []string `json:"md5"`
	MMH3               []string `json:"mmh3"`
	Regexp             []string `json:"regexp"`
	CompliedRegexp     []*regexp.Regexp
	CompiledVulnRegexp []*regexp.Regexp
	Header             []string `json:"header"`
	Vuln               []string `json:"vuln"`
}

type FingerMapper map[string][]*Finger

func (fm FingerMapper) GetFingers(port string) []*Finger {
	return fm[port]
}

type Fingers []*Finger

func (fs Fingers) Contain(f *Finger) bool {
	for _, finger := range fs {
		if f == finger {
			return true
		}
	}
	return false
}

func (fs Fingers) GroupByPort() FingerMapper {
	fingermap := make(FingerMapper)
	for _, f := range fs {
		for _, port := range f.Defaultport {
			fingermap[port] = append(fingermap[port], f)
		}
	}
	return fingermap
}

func LoadFingers(content []byte) (fingers Fingers, err error) {
	// 根据权重排序在python脚本中已经实现
	err = json.Unmarshal(content, &fingers)
	if err != nil {
		return nil, err
	}
	return fingers, nil
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
	return maptoString(v.Payload)
}

func (v *Vuln) GetDetail() string {
	return maptoString(v.Detail)
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
