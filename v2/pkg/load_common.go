package pkg

import (
	"encoding/json"
	"io/ioutil"
	"strings"

	"github.com/chainreactors/fingers/fingers"
	"github.com/chainreactors/parsers"
	"github.com/chainreactors/utils"
	"github.com/chainreactors/utils/iutils"
)

var (
	PresetPorts = utils.PrePort

	FingerEngine   *fingers.FingersEngine
	Extractor      []*parsers.Extractor
	Extractors     = make(parsers.Extractors)
	ExtractRegexps = map[string][]*parsers.Extractor{}
)

// LoadFinger 加载指纹到全局变量
func LoadFinger() error {
	var err error
	FingerEngine, err = fingers.NewFingersEngine(LoadConfig("http"), LoadConfig("socket"))
	if err != nil {
		return err
	}
	return nil
}

func LoadPortConfig(portConfig string) error {
	var ports []*utils.PortConfig
	var err error
	if portConfig == "" {
		err = json.Unmarshal(LoadConfig("port"), &ports)
		if err != nil {
			return err
		}
	} else {
		content, err := ioutil.ReadFile(portConfig)
		if err != nil {
			return err
		}
		err = json.Unmarshal(content, &ports)
		if err != nil {
			return err
		}
	}

	utils.PrePort = utils.NewPortPreset(ports)
	return nil
}

func LoadExtractor() {
	err := json.Unmarshal(LoadConfig("extract"), &Extractor)
	if err != nil {
		iutils.Fatal("extract config load FAIL!, " + err.Error())
	}

	for _, extract := range Extractor {
		extract.Compile()

		ExtractRegexps[extract.Name] = []*parsers.Extractor{extract}
		for _, tag := range extract.Tags {
			if _, ok := ExtractRegexps[tag]; !ok {
				ExtractRegexps[tag] = []*parsers.Extractor{extract}
			} else {
				ExtractRegexps[tag] = append(ExtractRegexps[tag], extract)
			}
		}
	}
}

func LoadWorkFlow() WorkflowMap {
	var workflows []*Workflow
	var err error
	err = json.Unmarshal(LoadConfig("workflow"), &workflows)
	if err != nil {
		iutils.Fatal("workflow load FAIL, " + err.Error())
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
		//if w.Path == "" {
		//	w.Path = "."
		//}
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
