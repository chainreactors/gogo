package fingers

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"

	"github.com/chainreactors/logs"
	"github.com/chainreactors/parsers"
	"github.com/chainreactors/utils"
)

func compileRegexp(s string) (*regexp.Regexp, error) {
	reg, err := regexp.Compile(s)
	if err != nil {
		return nil, err
	}
	return reg, nil
}

type Finger struct {
	Name        string   `yaml:"name" json:"name"`
	Protocol    string   `yaml:"protocol,omitempty" json:"protocol"`
	DefaultPort []string `yaml:"default_port,omitempty" json:"default_port,omitempty"`
	Focus       bool     `yaml:"focus,omitempty" json:"focus,omitempty"`
	Rules       Rules    `yaml:"rule,omitempty" json:"rule,omitempty"`
	Tags        []string `yaml:"tag,omitempty" json:"tag,omitempty"`
	IsActive    bool     `yaml:"-" json:"-"`
}

func (finger *Finger) Compile(portHandler func([]string) []string) error {
	if finger.Protocol == "" {
		finger.Protocol = "http"
	}

	if len(finger.DefaultPort) == 0 {
		if finger.Protocol == "http" {
			finger.DefaultPort = []string{"80"}
		}
	} else if portHandler != nil {
		finger.DefaultPort = portHandler(finger.DefaultPort)
	}

	err := finger.Rules.Compile(finger.Name)
	if err != nil {
		return err
	}

	for _, r := range finger.Rules {
		if r.IsActive {
			finger.IsActive = true
			break
		}
	}
	return nil
}

func (finger *Finger) ToResult(hasFrame, hasVuln bool, res string, index int) (frame *parsers.Framework, vuln *parsers.Vuln) {
	if index >= len(finger.Rules) {
		return nil, nil
	}

	if hasFrame {
		if res != "" {
			frame = &parsers.Framework{Name: finger.Name, Version: res}
		} else if finger.Rules[index].Version != "_" {
			frame = &parsers.Framework{Name: finger.Name, Version: finger.Rules[index].Version}
		} else {
			frame = &parsers.Framework{Name: finger.Name}
		}
	}

	if hasVuln {
		if finger.Rules[index].Vuln != "" {
			vuln = &parsers.Vuln{Name: finger.Rules[index].Vuln, SeverityLevel: HIGH}
		} else if finger.Rules[index].Info != "" {
			vuln = &parsers.Vuln{Name: finger.Rules[index].Info, SeverityLevel: INFO}
		} else {
			vuln = &parsers.Vuln{Name: finger.Name, SeverityLevel: INFO}
		}
	}
	return frame, vuln
}

func (finger *Finger) Match(content map[string]interface{}, level int, sender func([]byte) ([]byte, bool)) (*parsers.Framework, *parsers.Vuln, bool) {
	// sender用来处理需要主动发包的场景, 因为不通工具中的传入指不相同, 因此采用闭包的方式自定义result进行处理, 并允许添加更多的功能.
	// 例如在spray中, sender可以用来配置header等, 也可以进行特定的path拼接
	// 如果sender留空只进行被动的指纹判断, 将无视rules中的senddata字段

	for i, rule := range finger.Rules {
		if level < rule.Level {
			// 如果rule的rule小于指定的level等级, 则跳过该rule
			continue
		}

		var ishttp bool
		var isactive bool
		if finger.Protocol == "http" {
			ishttp = true
		}
		var c []byte
		var ok bool
		if rule.SendData != nil {
			c, ok = sender(rule.SendData)
			if ok {
				isactive = true
				content["content"] = bytes.ToLower(c)
			}
		}
		hasFrame, hasVuln, res := RuleMatcher(rule, content, ishttp)
		if hasFrame {
			frame, vuln := finger.ToResult(hasFrame, hasVuln, res, i)
			if finger.Focus {
				frame.IsFocus = true
			}
			//if vuln == nil && isactive {
			//	vuln = &parsers.Vuln{Name: finger.Name + " detect", SeverityLevel: INFO, Detail: map[string]interface{}{"path": rule.SendDataStr}}
			//}
			if isactive && hasFrame && ishttp {
				frame.Data = c
			}
			if frame.Version == "" && rule.Regexps.CompiledVersionRegexp != nil {
				for _, reg := range rule.Regexps.CompiledVersionRegexp {
					res, _ := compiledMatch(reg, content["content"].([]byte))
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
			frame.Tags = finger.Tags
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
	Cert                  []string         `yaml:"cert,omitempty" json:"cert,omitempty"`
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
	IsActive    bool      `yaml:"-" json:"-"`
}

func (r *Rule) Compile(name string) error {
	if r.Version == "" {
		r.Version = "_"
	}
	r.FingerName = name
	if r.SendDataStr != "" {
		r.SendData, _ = parsers.DSLParser(r.SendDataStr)
		if r.Level == 0 {
			r.Level = 1
		}
		r.IsActive = true
	}

	if r.Regexps != nil {
		err := r.Regexps.Compile()
		if err != nil {
			return err
		}
	}

	return nil
}

func (rs Rules) Compile(name string) error {
	for _, r := range rs {
		err := r.Compile(name)
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *Rule) Match(content []byte, ishttp bool) (bool, bool, string) {
	// 漏洞匹配优先
	for _, reg := range r.Regexps.CompiledVulnRegexp {
		res, ok := compiledMatch(reg, content)
		if ok {
			return true, true, res
		}
	}

	var body, header string
	if ishttp {
		cs := bytes.Index(content, []byte("\r\n\r\n"))
		if cs != -1 {
			body = string(content[cs+4:])
			header = string(content[:cs])
		}
	} else {
		body = string(content)
	}

	// body匹配
	for _, bodyReg := range r.Regexps.Body {
		if strings.Contains(body, bodyReg) {
			logs.Log.Debugf("%s finger hit, body: %s", r.FingerName, bodyReg)
			return true, false, ""
		}
	}

	// 正则匹配
	for _, reg := range r.Regexps.CompliedRegexp {
		res, ok := compiledMatch(reg, content)
		if ok {
			logs.Log.Debugf("%s finger hit, regexp: %s", r.FingerName, reg.String())
			return true, false, res
		}
	}

	// MD5 匹配
	for _, md5s := range r.Regexps.MD5 {
		if md5s == parsers.Md5Hash([]byte(body)) {
			logs.Log.Debugf("%s finger hit, md5: %s", r.FingerName, md5s)
			return true, false, ""
		}
	}

	// mmh3 匹配
	for _, mmh3s := range r.Regexps.MMH3 {
		if mmh3s == parsers.Mmh3Hash32([]byte(body)) {
			logs.Log.Debugf("%s finger hit, mmh3: %s", r.FingerName, mmh3s)
			return true, false, ""
		}
	}

	// http头匹配, http协议特有的匹配
	if !ishttp {
		return false, false, ""
	}

	for _, headerStr := range r.Regexps.Header {
		if strings.Contains(header, headerStr) {
			logs.Log.Debugf("%s finger hit, header: %s", r.FingerName, headerStr)
			return true, false, ""
		}
	}
	return false, false, ""
}

func (r *Rule) MatchCert(content string) bool {
	for _, cert := range r.Regexps.Cert {
		if strings.Contains(content, cert) {
			return true
		}
	}
	return false
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

type Fingers []*Finger

func (fs Fingers) GroupByPort() FingerMapper {
	fingermap := make(FingerMapper)
	for _, f := range fs {
		for _, port := range f.DefaultPort {
			fingermap[port] = append(fingermap[port], f)
		}
	}
	return fingermap
}

func (fs Fingers) GroupByMod() (Fingers, Fingers) {
	var active, passive Fingers
	for _, f := range fs {
		if f.IsActive {
			active = append(active, f)
		} else {
			passive = append(passive, f)
		}
	}
	return active, passive
}

// LoadFingers 加载指纹 迁移到fingers包从, 允许其他服务调用
func LoadFingers(content []byte) (fingers Fingers, err error) {
	err = json.Unmarshal(content, &fingers)
	if err != nil {
		return nil, err
	}

	for _, finger := range fingers {
		err := finger.Compile(utils.ParsePorts)
		if err != nil {
			return nil, err
		}
	}
	return fingers, nil
}
