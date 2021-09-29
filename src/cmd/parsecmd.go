package cmd

import (
	"fmt"
	"getitle/src/core"
	"getitle/src/scan"
	"getitle/src/utils"
	"strings"
)

func parseVersion(version, version2 bool) {
	//初始化全局变量
	if version {
		scan.VersionLevel = 1
	} else if version2 {
		scan.VersionLevel = 2
	} else {
		scan.VersionLevel = 0
	}
}

func parseExploit(exploit bool, exploitConfig string) {
	// 配置exploit
	if exploit {
		scan.Exploit = "auto"
	} else if !exploit && exploitConfig != "none" {
		scan.Exploit = exploitConfig
	} else {
		scan.Exploit = exploitConfig
	}
}

func parseFilename(nofilename bool, config *utils.Config) {
	if !nofilename && config.Filename == "" {
		basefilename := joinFilename(*config)
		i := 1
		for core.CheckFileIsExist(basefilename + utils.ToString(i) + ".json") {
			i++
		}
		config.Filename = basefilename + utils.ToString(i) + ".json"
	}
}

func joinFilename(config utils.Config) string {
	var target string
	if config.IP != "" {
		target = strings.Replace(core.IpForamt(config.IP), "/", "_", -1)
	} else if config.ListFile != "" {
		target = config.ListFile
	} else if config.Mod == "a" {
		target = "auto"
	}
	return fmt.Sprintf(".%s_%s_", target, config.Ports)
}
