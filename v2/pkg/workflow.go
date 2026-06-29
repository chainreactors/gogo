package pkg

import (
	"fmt"
	"gopkg.in/yaml.v3"

	"github.com/chainreactors/utils/parsers"
)

func ParseWorkflowsFromInput(content []byte) ([]*Workflow, error) {
	var workflows []*Workflow
	err := yaml.Unmarshal(content, &workflows)
	if err != nil {
		return nil, fmt.Errorf("workflow load FAIL, %s", err.Error())
	}
	return workflows, nil
}

type Workflow struct {
	Name        string   `json:"name" yaml:"name"`
	Description string   `json:"description" yaml:"description"`
	IP          string   `json:"ip" yaml:"ip"`
	IPlist      []string `json:"iplist" yaml:"iplist"`
	Ports       string   `json:"ports" yaml:"ports"`
	Mod         string   `json:"mod" yaml:"mod"`
	Ping        bool     `json:"ping" yaml:"ping"`
	NoScan      bool     `json:"no-scan" yaml:"no-scan"`
	IpProbe     string   `json:"ip-probe" yaml:"ip-probe"`
	PortProbe   string   `json:"port-probe" yaml:"port-probe"`
	Exploit     string   `json:"exploit" yaml:"exploit"`
	Verbose     int      `json:"verbose" yaml:"verbose"`
	File        string   `json:"file" yaml:"file"`
	Path        string   `json:"path" yaml:"path"`
	Tags        []string `json:"tags" yaml:"tags"`
}

func (w *Workflow) Marshal() string {
	out, err := yaml.Marshal(w)
	if err != nil {
		return ""
	}
	return string(out)
}

func (w *Workflow) PrepareConfig(rconfig Config) *Config {
	var config = &Config{
		RunnerOpt: rconfig.RunnerOpt,
		GOGOConfig: &parsers.GOGOConfig{
			IP:       w.IP,
			IPlist:   w.IPlist,
			ListFile: rconfig.ListFile,
			JsonFile: rconfig.JsonFile,
			Ports:    w.Ports,
			Mod:      w.Mod,
		},
		Excludes:    rconfig.Excludes,
		IpProbe:     w.IpProbe,
		PortProbe:   w.PortProbe,
		FilePath:    w.Path,
		Outputf:     "full",
		FileOutputf: "json",
		Tee:         rconfig.Tee,
		Compress:    rconfig.Compress,
	}

	if rconfig.FilePath != "" {
		config.FilePath = rconfig.FilePath
	}

	// 一些workflow的参数, 允许被命令行参数覆盖
	if rconfig.IP != "" {
		config.IP = rconfig.IP
	}

	if rconfig.ListFile != "" {
		config.ListFile = rconfig.ListFile
	}

	if rconfig.Ports != "top1" {
		config.Ports = rconfig.Ports
	}

	if w.Ping {
		config.AliveSprayMod = append(config.AliveSprayMod, "icmp")
	}

	if w.Mod == "" {
		config.Mod = Default
	}

	if rconfig.Threads != 0 {
		config.Threads = rconfig.Threads
	}

	if rconfig.PortProbe != Default {
		config.PortProbe = rconfig.PortProbe
	}

	if rconfig.IpProbe != Default {
		config.IpProbe = rconfig.IpProbe
	}

	if rconfig.Outputf != "full" {
		config.Outputf = rconfig.Outputf
	}

	if rconfig.FileOutputf != "json" {
		config.FileOutputf = rconfig.FileOutputf
	}

	if rconfig.Filename != "" {
		config.Filename = rconfig.Filename
	}

	if rconfig.Filenamef != "" {
		config.Filenamef = rconfig.Filenamef
	} else if w.File != "" {
		if w.File == "auto" {
			config.Filenamef = "auto"
		}
	}

	return config
}
