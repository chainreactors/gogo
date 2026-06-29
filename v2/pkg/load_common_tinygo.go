//go:build tinygo && !emptytemplates
// +build tinygo,!emptytemplates

package pkg

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/chainreactors/fingers/fingerprinthub"
	"github.com/chainreactors/fingers/fingers"
	"github.com/chainreactors/fingers/resources"
	"github.com/chainreactors/utils/parsers"
	"github.com/chainreactors/utils"
)

var (
	FingerEngine         *fingers.FingersEngine
	FingerprintHubEngine *fingerprinthub.FingerPrintHubEngine
	Extractor            []*parsers.Extractor
	Extractors           = make(parsers.Extractors)
	ExtractRegexps       = map[string][]*parsers.Extractor{}
)

func LoadFinger(fileutils []string) error {
	var err error
	resources.PrePort = utils.PrePort

	httpfs, err := fingers.LoadFingers(LoadConfig("http"))
	if err != nil {
		return err
	}

	socketfs, err := fingers.LoadFingers(LoadConfig("socket"))
	if err != nil {
		return err
	}

	FingerEngine, err = fingers.NewEngine(httpfs, socketfs)
	if err != nil {
		return err
	}

	FingerprintHubEngine, err = fingerprinthub.NewFingerPrintHubEngine(
		LoadConfig("fingerprinthub_web"),
		[]byte("[]"),
	)
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
	Extractor = nil
	Extractors = make(parsers.Extractors)
	ExtractRegexps = map[string][]*parsers.Extractor{}

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

func LoadWorkFlow() (WorkflowMap, error) {
	var workflows []*Workflow
	err := yaml.Unmarshal(LoadConfig("workflow"), &workflows)
	if err != nil {
		return nil, fmt.Errorf("workflow load FAIL, %s", err.Error())
	}

	for _, w := range workflows {
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
		if w.Exploit == "" {
			w.Exploit = "none"
		}
	}

	tmpmap := make(map[string][]*Workflow)
	for _, workflow := range workflows {
		tmpmap[strings.ToLower(workflow.Name)] = append(tmpmap[strings.ToLower(workflow.Name)], workflow)
		for _, tag := range workflow.Tags {
			tmpmap[strings.ToLower(tag)] = append(tmpmap[strings.ToLower(tag)], workflow)
		}
	}
	return tmpmap, nil
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
