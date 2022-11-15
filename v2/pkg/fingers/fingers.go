package fingers

import (
	"encoding/json"
	"fmt"
	"github.com/chainreactors/ipcs"
	"github.com/chainreactors/logs"
	. "github.com/chainreactors/parsers"
	"regexp"
	"strings"
)

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
	DefaultPort []string `yaml:"default_port,omitempty" json:"default_port,omitempty"`
	Focus       bool     `yaml:"focus,omitempty" json:"focus,omitempty"`
	Rules       Rules    `yaml:"rule,omitempty" json:"rule,omitempty"`
	Tag         string   `yaml:"tag,omitempty" json:"tag,omitempty"`
}

func (finger *Finger) Compile(portHandler func([]string) []string) error {
	if finger.Protocol == "" {
		finger.Protocol = "http"
	}

	if len(finger.DefaultPort) == 0 {
		if finger.Protocol == "http" {
			finger.DefaultPort = []string{"80"}
		}
	} else {
		finger.DefaultPort = portHandler(finger.DefaultPort)
	}

	err := finger.Rules.Compile(finger.Name)
	if err != nil {
		return err
	}
	return nil
}

func (finger *Finger) ToResult(hasFrame, hasVuln bool, res string, index int) (frame *Framework, vuln *Vuln) {
	if index+1 > len(finger.Rules) {
		return nil, nil
	}

	if hasFrame {
		if res != "" {
			frame = &Framework{Name: finger.Name, Version: res}
		} else if finger.Rules[index].Version != "" {
			frame = &Framework{Name: finger.Name, Version: res}
		} else {
			frame = &Framework{Name: finger.Name}
		}
	}

	if hasVuln {
		if finger.Rules[index].Vuln != "" {
			vuln = &Vuln{Name: finger.Rules[index].Vuln, SeverityLevel: HIGH}
		} else if finger.Rules[index].Info != "" {
			vuln = &Vuln{Name: finger.Rules[index].Info, SeverityLevel: INFO}
		} else {
			vuln = &Vuln{Name: finger.Name, SeverityLevel: INFO}
		}
	}
	return frame, vuln
}

func (finger *Finger) Match(content string, level int, sender func([]byte) (string, bool)) (*Framework, *Vuln, bool) {
	// 只进行被动的指纹判断, 将无视rules中的senddata字段
	for i, rule := range finger.Rules {
		var ishttp bool
		var isactive bool
		if finger.Protocol == "http" {
			ishttp = true
		}
		var c string
		var ok bool
		if level >= rule.Level && rule.SendData != nil {
			logs.Log.Debugf("active match with %s", rule.SendDataStr)
			c, ok = sender(rule.SendData)
			if ok {
				isactive = true
				content = strings.ToLower(c)
			}
		}
		hasFrame, hasVuln, res := RuleMatcher(rule, content, ishttp)
		if hasFrame {
			frame, vuln := finger.ToResult(hasFrame, hasVuln, res, i)
			if finger.Focus {
				frame.IsFocus = true
			}
			if isactive && hasFrame && ishttp {
				frame.Data = c
			}
			if frame.Version == "" && rule.Regexps.CompiledVersionRegexp != nil {
				for _, reg := range rule.Regexps.CompiledVersionRegexp {
					res, _ := compiledMatch(reg, content)
					if res != "" {
						logs.Log.Debugf("%s version hit, regexp: %s", finger.Name, reg.String())
						frame.Version = res
						break
					}
				}
			}
			if isactive {
				frame.From = ACTIVE
			}
			frame.Tag = finger.Tag
			return frame, vuln, true
		}
	}
	return nil, nil, false
}

type Regexps struct {
	Body                  []string         `yaml:"body,omitempty" json:"body,omitempty"`
	MD5                   []string         `yaml:"md5,omitempty" json:"md5,omitempty"`
	MMH3                  []string         `yaml:"mmh3,omitempty" json:"mmh3,omitempty"`
	Regexp                []string         `yaml:"regexp,omitempty" json:"regexp,omitempty"`
	Version               []string         `yaml:"version,omitempty" json:"version,omitempty"`
	CompliedRegexp        []*regexp.Regexp `yaml:"-" json:"-"`
	CompiledVulnRegexp    []*regexp.Regexp `yaml:"-" json:"-"`
	CompiledVersionRegexp []*regexp.Regexp `yaml:"-" json:"-"`
	FingerName            string           `yaml:"-" json:"-"`
	Header                []string         `yaml:"header,omitempty" json:"header,omitempty"`
	Vuln                  []string         `yaml:"vuln,omitempty" json:"vuln,omitempty"`
}

func (r *Regexps) Compile() error {
	for _, reg := range r.Regexp {
		creg, err := compileRegexp("(?i)" + reg)
		if err != nil {
			return err
		}
		r.CompliedRegexp = append(r.CompliedRegexp, creg)
	}

	for _, reg := range r.Vuln {
		creg, err := compileRegexp("(?i)" + reg)
		if err != nil {
			return err
		}
		r.CompiledVulnRegexp = append(r.CompiledVulnRegexp, creg)
	}

	for _, reg := range r.Version {
		creg, err := compileRegexp(reg)
		if err != nil {
			return err
		}
		r.CompiledVersionRegexp = append(r.CompiledVersionRegexp, creg)
	}

	for i, b := range r.Body {
		r.Body[i] = strings.ToLower(b)
	}

	for i, h := range r.Header {
		r.Header[i] = strings.ToLower(h)
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
	SendDataStr string    `yaml:"send_data,omitempty" json:"send_data,omitempty"`
	SendData    senddata  `yaml:"-" json:"-"`
	Info        string    `yaml:"info,omitempty" json:"info,omitempty"`
	Vuln        string    `yaml:"vuln,omitempty" json:"vuln,omitempty"`
	Level       int       `yaml:"level,omitempty" json:"level,omitempty"`
	FingerName  string    `yaml:"-" json:"-"`
}

func (rs Rules) Compile(name string) error {
	for _, r := range rs {
		if r.Version == "" {
			r.Version = "_"
		}
		r.FingerName = name
		if r.SendDataStr != "" {
			r.SendData, _ = DSLParser(r.SendDataStr)
			if r.Level == 0 {
				r.Level = 1
			}
		}

		if r.Regexps != nil {
			err := r.Regexps.Compile()
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (rule *Rule) Match(content string, ishttp bool) (bool, bool, string) {
	// 漏洞匹配优先
	if rule.Regexps == nil {
		return false, false, ""
	}
	for _, reg := range rule.Regexps.CompiledVulnRegexp {
		res, ok := compiledMatch(reg, content)
		if ok {
			return true, true, res
		}
	}

	var body, header string
	if ishttp {
		cs := strings.Index(content, "\r\n\r\n")
		if cs != -1 {
			body = content[cs+4:]
			header = content[:cs]
		}
	} else {
		body = content
	}

	// body匹配
	for _, bodyReg := range rule.Regexps.Body {
		if strings.Contains(body, bodyReg) {
			logs.Log.Debugf("%s finger hit, body: %s", rule.FingerName, bodyReg)
			return true, false, ""
		}
	}

	// 正则匹配
	for _, reg := range rule.Regexps.CompliedRegexp {
		res, ok := compiledMatch(reg, content)
		if ok {
			logs.Log.Debugf("%s finger hit, regexp: %s", rule.FingerName, reg.String())
			return true, false, res
		}
	}

	// MD5 匹配
	for _, md5s := range rule.Regexps.MD5 {
		if md5s == Md5Hash([]byte(content)) {
			logs.Log.Debugf("%s finger hit, md5: %s", rule.FingerName, md5s)
			return true, false, ""
		}
	}

	// mmh3 匹配
	for _, mmh3s := range rule.Regexps.MMH3 {
		if mmh3s == Mmh3Hash32([]byte(content)) {
			logs.Log.Debugf("%s finger hit, mmh3: %s", rule.FingerName, mmh3s)
			return true, false, ""
		}
	}

	// http头匹配, http协议特有的匹配
	if !ishttp {
		return false, false, ""
	}

	for _, headerStr := range rule.Regexps.Header {
		if strings.Contains(header, headerStr) {
			logs.Log.Debugf("%s finger hit, header: %s", rule.FingerName, headerStr)
			return true, false, ""
		}
	}
	return false, false, ""
}

type Rules []*Rule

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
		for _, port := range f.DefaultPort {
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

	for _, finger := range fingers {
		err := finger.Compile(ipcs.ParsePorts)
		if err != nil {
			return nil, err
		}
	}
	return fingers, nil
}
