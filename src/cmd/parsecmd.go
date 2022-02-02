package cmd

import (
	"fmt"
	. "getitle/src/core"
	. "getitle/src/scan"
	. "getitle/src/utils"
	"path"
	"regexp"
	"strings"
)

func parseVersion(version, version2 bool) {
	//初始化全局变量
	if version {
		RunOpt.VersionLevel = 1
	} else if version2 {
		RunOpt.VersionLevel = 2
	} else {
		RunOpt.VersionLevel = 0
	}
}

func parseExploit(exploit bool, exploitConfig string) {
	// 配置exploit
	if exploit {
		RunOpt.Exploit = "auto"
	} else if !exploit && exploitConfig != "none" {
		RunOpt.Exploit = exploitConfig
	} else {
		RunOpt.Exploit = exploitConfig
	}
}

func parseFilename(autofile, hiddenfile bool, config *Config) {
	if config.Filename == "" {
		config.Filename = GetFilename(*config, autofile, hiddenfile, Opt.FileOutput)
	} else {
		path.Join(Opt.FilePath, config.Filename)
	}
	if config.IsSmartScan() && !Opt.Noscan {
		config.SmartFilename = GetFilename(*config, autofile, hiddenfile, "cidr")
	}

	if config.Ping {
		config.PingFilename = GetFilename(*config, autofile, hiddenfile, "ping")
	}
}

func printConfigs(t string) {
	if t == "port" {
		TagMap, NameMap, PortMap = LoadPortConfig()
		Printportconfig()
	} else if t == "nuclei" {
		LoadNuclei("")
		PrintNucleiPoc()
	} else if t == "inter" {
		PrintInterConfig()
	} else {
		fmt.Println("choice port|nuclei|inter")
	}
}

func parseExtractors(extracts arrayFlags, extractStr string) {
	if extractStr != "" {
		exts := strings.Split(extractStr, ",")
		for _, extract := range exts {
			if reg, ok := PresetExtracts[extract]; ok {
				Extractors[extract] = reg
			}
		}
	}
	for _, extract := range extracts {
		if reg, ok := PresetExtracts[extract]; ok {
			Extractors[extract] = reg
		} else {
			Extractors[extract] = CompileRegexp(extract)
		}
	}
}

func nucleiLoader(pocfile string, payloads arrayFlags) {
	ExecuterOptions = ParserCmdPayload(payloads)
	TemplateMap = LoadNuclei(pocfile)
}

func configloader() {
	Compiled = make(map[string][]*regexp.Regexp)
	Mmh3Fingers, Md5Fingers = LoadHashFinger()
	TcpFingers = LoadFingers("tcp")
	HttpFingers = LoadFingers("http")
	TagMap, NameMap, PortMap = LoadPortConfig()
	CommonCompiled = map[string]*regexp.Regexp{
		"title":     CompileRegexp("(?Uis)<title>(.*)</title>"),
		"server":    CompileRegexp("(?i)Server: ([\x20-\x7e]+)"),
		"xpb":       CompileRegexp("(?i)X-Powered-By: ([\x20-\x7e]+)"),
		"sessionid": CompileRegexp("(?i) (.*SESS.*?ID)"),
	}
}
