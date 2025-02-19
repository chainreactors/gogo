package pkg

import (
	"gopkg.in/yaml.v3"

	"github.com/chainreactors/parsers"
	"github.com/chainreactors/utils/iutils"
)

func ParseWorkflowsFromInput(content []byte) []*Workflow {
	var workflows []*Workflow
	var err error
	err = yaml.Unmarshal(content, &workflows)
	if err != nil {
		iutils.Fatal("workflow load FAIL, " + err.Error())
	}
	return workflows
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
	SmartProbe  string   `json:"port-probe" yaml:"port-probe"`
	Exploit     string   `json:"exploit" yaml:"exploit"`
	Verbose     int      `json:"verbose" yaml:"verbose"`
	File        string   `json:"file" yaml:"file"`
	Path        string   `json:"path" yaml:"path"`
	Tags        []string `json:"tags" yaml:"tags"`
}

func (w *Workflow) PrepareConfig(rconfig Config) *Config {
	var config = &Config{
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
		PortProbe:   w.SmartProbe,
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
