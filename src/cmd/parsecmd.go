package cmd

import (
	"fmt"
	"getitle/src/core"
	"getitle/src/scan"
	"getitle/src/structutils"
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

func parseFilename(autofilename bool, config *utils.Config) {
	if autofilename && config.Filename == "" {
		basefilename := fmt.Sprintf(".%s_%s_", parseTarget(config), config.Ports)
		i := 1
		for core.CheckFileIsExist(basefilename + structutils.ToString(i) + ".json") {
			i++
		}
		config.Filename = basefilename + structutils.ToString(i) + ".json"

		if config.IsSmart() {
			i := 1
			smartbasename := fmt.Sprintf(".%s_%s_", parseTarget(config), config.Mod)
			for core.CheckFileIsExist(smartbasename + structutils.ToString(i) + ".json") {
				i++
			}
			config.SmartFilename = smartbasename + structutils.ToString(i) + ".json"
		}
	}
}

func parseTarget(config *utils.Config) string {
	var target string
	if config.IP != "" {
		target = strings.Replace(core.IpForamt(config.IP), "/", "_", -1)
	} else if config.ListFile != "" {
		target = config.ListFile
	} else if config.JsonFile != "" {
		target = config.JsonFile
	} else if config.Mod == "a" {
		target = "auto"
	}
	return target
}
