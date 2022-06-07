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

func mapToString(m map[string]interface{}) string {
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
	Name        string   `yaml:"name" json:"name"`
	Protocol    string   `yaml:"protocol,omitempty" json:"protocol"`
	Defaultport []string `yaml:"default_port,omitempty" json:"default_port,omitempty"`
	Rules       Rules    `yaml:"rule,omitempty" json:"rule,omitempty"`
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

	err := f.Rules.Compile()
	if err != nil {
		return err
	}
	return nil
}

func (f *Finger) ToResult(hasFrame, hasVuln bool, res string, index int) (frame *Framework, vuln *Vuln) {
	if index+1 > len(f.Rules) {
		return nil, nil
	}

	if hasFrame {
		if res != "" {
			frame = &Framework{Name: f.Name, Version: res}
		} else if f.Rules[index].Version != "" {
			frame = &Framework{Name: f.Name, Version: res}
		} else {
			frame = &Framework{Name: f.Name}
		}
	}

	if hasVuln {
		if f.Rules[index].Vuln != "" {
			vuln = &Vuln{Name: f.Rules[index].Vuln, Severity: "high"}
		} else if f.Rules[index].Info != "" {
			vuln = &Vuln{Name: f.Rules[index].Info, Severity: "info"}
		} else {
			vuln = &Vuln{Name: f.Name, Severity: "info"}
		}
	}
	return frame, vuln
}

type Regexps struct {
	Body               []string         `yaml:"body,omitempty" json:"body,omitempty"`
	MD5                []string         `yaml:"md5,omitempty" json:"md5,omitempty"`
	MMH3               []string         `yaml:"mmh3,omitempty" json:"mmh3,omitempty"`
	Regexp             []string         `yaml:"regexp,omitempty" json:"regexp"`
	CompliedRegexp     []*regexp.Regexp `yaml:"-" json:"-"`
	CompiledVulnRegexp []*regexp.Regexp `yaml:"-" json:"-"`
	Header             []string         `yaml:"header,omitempty" json:"header,omitempty"`
	Vuln               []string         `yaml:"vuln,omitempty" json:"vuln,omitempty"`
}

func (r *Regexps) RegexpCompile() error {
	for _, reg := range r.Regexp {
		creg, err := compileRegexp(reg)
		if err != nil {
			return err
		}
		r.CompliedRegexp = append(r.CompliedRegexp, creg)
	}

	for _, reg := range r.Vuln {
		creg, err := compileRegexp(reg)
		if err != nil {
			return err
		}
		r.CompiledVulnRegexp = append(r.CompiledVulnRegexp, creg)
	}
	return nil
}

type Favicons struct {
	Mmh3 []string `yaml:"mmh3,omitempty" json:"mmh3,omitempty"`
	Md5  []string `yaml:"md5,omitempty" json:"md5,omitempty"`
}

type Rule struct {
	Version     string    `yaml:"version,omitempty" json:"version,omitempty"`
	Favicon     *Favicons `yaml:"favicon,omitempty" json:"favicon,omitempty"`
	Regexps     *Regexps  `yaml:"regexps,omitempty" json:"regexps,omitempty"`
	SendDataStr string    `yaml:"send_data,omitempty" json:"send_data_str,omitempty"`
	SendData    senddata  `yaml:"-" json:"-,omitempty"`
	Info        string    `yaml:"info,omitempty" json:"info,omitempty"`
	Vuln        string    `yaml:"vuln,omitempty" json:"vuln,omitempty"`
	Level       int       `yaml:"level,omitempty" json:"level,omitempty"`
}

func (r *Rule) dataDecode() {
	if r.SendDataStr != "" {
		r.SendData = decode(r.SendDataStr)
	}
	// todo
	// regexp decode
}

type Rules []*Rule

func (rs Rules) Compile() error {
	for _, r := range rs {
		r.dataDecode()
		if r.Regexps != nil {
			err := r.Regexps.RegexpCompile()
			if err != nil {
				return err
			}
		}
	}
	return nil
}

type senddata []byte

func (d senddata) IsNull() bool {
	if len(d) == 0 {
		return true
	}
	return false
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
	err = json.Unmarshal(content, &fingers)
	if err != nil {
		return nil, err
	}
	return fingers, nil
}

type Framework struct {
	Name    string `json:"ft"`
	Version string `json:"fv"`
	From    string `json:"ff"`
	IsGuess bool   `json:"fg"`
}

func (f Framework) ToString() string {
	var s = f.Name
	if f.IsGuess {
		s = "*" + s
	}
	if f.Version != "" {
		s += " " + f.Version
	}
	if f.From != "" {
		s += ":" + f.From
	}
	return s
}

const (
	Info int = iota + 1
	Medium
	High
	Critical
)

var serverityMap = map[string]int{
	"info":     Info,
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
	return mapToString(v.Payload)
}

func (v *Vuln) GetDetail() string {
	return mapToString(v.Detail)
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
