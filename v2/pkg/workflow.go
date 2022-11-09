package pkg

import (
	"encoding/json"
	"github.com/chainreactors/gogo/v2/pkg/utils"
	"github.com/chainreactors/parsers"
)

func ParseWorkflowsFromInput(content []byte) []*Workflow {
	var workflows []*Workflow
	var err error
	err = json.Unmarshal(content, &workflows)
	if err != nil {
		utils.Fatal("workflow load FAIL, " + err.Error())
	}
	return workflows
}

type Workflow struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	IP          string   `json:"ip"`
	IPlist      []string `json:"iplist"`
	Ports       string   `json:"ports"`
	Mod         string   `json:"mod"`
	Ping        bool     `json:"ping"`
	NoScan      bool     `json:"no-scan"`
	IpProbe     string   `json:"ipprobe"`
	SmartProbe  string   `json:"portprobe"`
	Exploit     string   `json:"exploit"`
	Verbose     int      `json:"verbose"`
	File        string   `json:"file"`
	Path        string   `json:"path"`
	Tags        []string `json:"tags"`
}

func (w *Workflow) PrepareConfig(rconfig Config) *Config {
	var config = &Config{
		GOGOConfig: &parsers.GOGOConfig{
			IP:     w.IP,
			IPlist: w.IPlist,
			Ports:  w.Ports,
			Mod:    w.Mod,
		},
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

	//if rconfig.FileOutputf == Default && config.Mod == SUPERSMARTB {
	//	config.FileOutputf = "raw"
	//}

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
