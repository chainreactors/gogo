package pkg

import (
	"encoding/json"
	"github.com/chainreactors/gogo/v2/pkg/fingers"
	"github.com/chainreactors/gogo/v2/pkg/utils"
	"github.com/chainreactors/ipcs"
	"strings"
)

var (
	NameMap = ipcs.NameMap
	PortMap = ipcs.PortMap
	TagMap  = ipcs.TagMap
	//WorkFlowMap    map[string][]*Workflow
	Extractors = make(fingers.Extractors)
)

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
			w.IpProbe = Default
		}
		if w.SmartProbe == "" {
			w.SmartProbe = Default
		}
		if w.Ports == "" {
			w.Ports = "top1"
		}
		if w.Mod == "" {
			w.Mod = Default
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
