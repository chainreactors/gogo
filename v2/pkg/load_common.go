package pkg

import (
	"github.com/chainreactors/fingers/resources"
	"gopkg.in/yaml.v3"
	"strings"

	"github.com/chainreactors/fingers/fingers"
	"github.com/chainreactors/parsers"
	"github.com/chainreactors/utils"
	"github.com/chainreactors/utils/iutils"
)

var (
	FingerEngine   *fingers.FingersEngine
	Extractor      []*parsers.Extractor
	Extractors     = make(parsers.Extractors)
	ExtractRegexps = map[string][]*parsers.Extractor{}
)

// LoadFinger 加载指纹到全局变量
func LoadFinger(fileutils []string) error {
	var err error
	resources.PrePort = utils.PrePort
	resources.FingersHTTPData = LoadConfig("http")
	resources.FingersSocketData = LoadConfig("socket")
	FingerEngine, err = fingers.NewFingersEngine()
	if err != nil {
		return err
	}

	for _, file := range fileutils {
		content, err := LoadResource(file)
		if err != nil {
			return err
		}
		var fs fingers.Fingers
		err = yaml.Unmarshal(content, &fs)
		if err != nil {
			return err
		}
		err = FingerEngine.Append(fs)
		if err != nil {
			return err
		}
	}

	return nil
}

func LoadPortConfig(portConfig string) error {
	var ports []*utils.PortConfig
	var err error
	if portConfig == "" {
		err = yaml.Unmarshal(LoadConfig("port"), &ports)
		if err != nil {
			return err
		}
	} else {
		content, err := LoadResource(portConfig)
		if err != nil {
			return err
		}
		err = yaml.Unmarshal(content, &ports)
		if err != nil {
			return err
		}
	}

	utils.PrePort = utils.NewPortPreset(ports)
	return nil
}

func LoadExtractor() error {
	err := yaml.Unmarshal(LoadConfig("extract"), &Extractor)
	if err != nil {
		return err
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
	return nil
}

func LoadWorkFlow() WorkflowMap {
	var workflows []*Workflow
	var err error
	err = yaml.Unmarshal(LoadConfig("workflow"), &workflows)
	if err != nil {
		iutils.Fatal("workflow load FAIL, " + err.Error())
	}

	// 设置默认参数
	for _, w := range workflows {
		// 参数默认值
		if w.IpProbe == "" {
			w.IpProbe = Default
		}
		if w.PortProbe == "" {
			w.PortProbe = Default
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
