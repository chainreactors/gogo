package pkg

import (
	"encoding/json"
	"github.com/chainreactors/gogo/v1/pkg/utils"
	"github.com/chainreactors/ipcs"
	"regexp"
	"strings"
)

var (
	NameMap = ipcs.NameMap
	PortMap = ipcs.PortMap
	TagMap  = ipcs.TagMap
	//WorkFlowMap    map[string][]*Workflow
	CommonCompiled map[string]*regexp.Regexp
	Extractors     = make(map[string]*regexp.Regexp)
)

var PresetExtracts = map[string]*regexp.Regexp{
	"url":      regexp.MustCompile("^(http(s)?:\\/\\/)[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+(:[0-9]{1,5})?[-a-zA-Z0-9()@:%_\\\\\\+\\.~#?&//=]*$"),
	"ip":       regexp.MustCompile("((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})(\\.((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})){3}"),
	"mail":     regexp.MustCompile("^([A-Za-z0-9_\\-\\.\u4e00-\u9fa5])+\\@([A-Za-z0-9_\\-\\.])+\\.([A-Za-z]{2,8})$"),
	"idcard":   regexp.MustCompile("^(\\d{15}$)|(^\\d{17}([0-9]|[xX]))$"),
	"phone":    regexp.MustCompile("^(\\+?0?86\\-?)?1[3-9]\\d{9}$"),
	"header":   regexp.MustCompile("(?U)^HTTP(?:.|\n)*[\r\n]{4}"),
	"body":     regexp.MustCompile("[\\r\\n]{4}[\\w\\W]*"),
	"cookie":   regexp.MustCompile("(?i)Set-Cookie.*"),
	"response": regexp.MustCompile("(?s).*"),
}

type PortFinger struct {
	Name  string   `json:"name"`
	Ports []string `json:"ports"`
	Type  []string `json:"type"`
}

func LoadPortConfig() {
	var portfingers []PortFinger
	err := json.Unmarshal(LoadConfig("port"), &portfingers)

	if err != nil {
		utils.Fatal("port config load FAIL!, " + err.Error())
	}
	for _, v := range portfingers {
		v.Ports = ipcs.ParsePorts(v.Ports)
		ipcs.NameMap.Append(v.Name, v.Ports...)
		for _, t := range v.Type {
			ipcs.TagMap.Append(t, v.Ports...)
		}
		for _, p := range v.Ports {
			ipcs.PortMap.Append(p, v.Name)
		}
	}
}

func LoadWorkFlow() WorkflowMap {
	var workflows []*Workflow
	var err error
	err = json.Unmarshal(LoadConfig("workflow"), &workflows)
	if err != nil {
		utils.Fatal("workflow load FAIL, " + err.Error())
	}

	// 设置默认参数
	for _, w := range workflows {
		// 参数默认值
		if w.IpProbe == "" {
			w.IpProbe = "default"
		}
		if w.SmartProbe == "" {
			w.SmartProbe = "default"
		}
		if w.Ports == "" {
			w.Ports = "top1"
		}
		if w.Mod == "" {
			w.Mod = "default"
		}
		if w.File == "" {
			w.File = "auto"
		}
		if w.Exploit == "" {
			w.Exploit = "none"
		}
	}

	var tmpmap = make(map[string][]*Workflow)
	for _, workflow := range workflows {
		tmpmap[strings.ToLower(workflow.Name)] = append(tmpmap[strings.ToLower(workflow.Name)], workflow)
		for _, tag := range workflow.Tags {
			tmpmap[strings.ToLower(tag)] = append(tmpmap[strings.ToLower(tag)], workflow)
		}
	}
	return tmpmap
}

type WorkflowMap map[string][]*Workflow

func (m WorkflowMap) Choice(name string) []*Workflow {
	var workflows []*Workflow
	name = strings.TrimSpace(name)
	names := strings.Split(name, ",")
	for _, n := range names {
		workflows = append(workflows, m[strings.ToLower(n)]...)
	}
	return workflows
}
