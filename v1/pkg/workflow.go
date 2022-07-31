package pkg

import (
	"encoding/json"
	"getitle/v1/pkg/utils"
)

type Workflow struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	IP          string   `json:"ip"`
	IPlist      []string `json:"iplist"`
	Ports       string   `json:"ports"`
	Mod         string   `json:"mod"`
	Ping        bool     `json:"ping"`
	Arp         bool     `json:"arp"`
	NoScan      bool     `json:"no-scan"`
	IpProbe     string   `json:"ipprobe"`
	SmartProbe  string   `json:"portprobe"`
	Exploit     string   `json:"exploit"`
	Version     int      `json:"version"`
	File        string   `json:"file"`
	Path        string   `json:"path"`
	Tags        []string `json:"tags"`
}

func ParseWorkflowsFromInput(content []byte) []*Workflow {
	var workflows []*Workflow
	var err error
	err = json.Unmarshal(content, &workflows)
	if err != nil {
		utils.Fatal("workflow load FAIL, " + err.Error())
	}
	return workflows
}

func (w *Workflow) PrepareConfig(rconfig Config) *Config {
	var config = &Config{
		IP:        w.IP,
		IPlist:    w.IPlist,
		Ports:     w.Ports,
		Mod:       w.Mod,
		IpProbe:   w.IpProbe,
		SmartPort: w.SmartProbe,
		FilePath:  w.Path,
	}

	if rconfig.FilePath != "" {
		config.FilePath = rconfig.FilePath
	}

	//if rconfig.FileOutputf == "default" && config.Mod == "sc" {
	//	config.FileOutputf = "raw"
	//}

	// 一些workflow的参数, 允许被命令行参数覆盖
	if rconfig.IP != "" {
		config.IP = rconfig.IP
	}

	if rconfig.ListFile != "" {
		config.ListFile = rconfig.ListFile
	}

	if rconfig.Ports != "" {
		config.Ports = rconfig.Ports
	}

	if w.Arp {
		config.AliveSprayMod = append(config.AliveSprayMod, "arp")
	}
	if w.Ping {
		config.AliveSprayMod = append(config.AliveSprayMod, "icmp")
	}

	if w.Mod == "" {
		config.Mod = "default"
	}

	if rconfig.Threads != 0 {
		config.Threads = rconfig.Threads
	}

	if rconfig.SmartPort != "default" {
		config.SmartPort = rconfig.SmartPort
	}

	if rconfig.IpProbe != "default" {
		config.IpProbe = rconfig.IpProbe
	}

	if w.File == "auto" {
		config.Filenamef = "auto"
	}

	if rconfig.FileOutputf != "default" {
		config.FileOutputf = "json"
	} else {
		config.FileOutputf = rconfig.FileOutputf
	}

	if w.File != "" {
		config.Filename = GetFilename(config, "json")
		if config.IsSmart() {
			config.SmartFilename = GetFilename(config, "cidr")
		}
		if config.HasAlivedScan() {
			config.AlivedFilename = GetFilename(config, "alived")
		}
	}

	return config
}
