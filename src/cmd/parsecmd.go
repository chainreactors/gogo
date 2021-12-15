package cmd

import (
	"getitle/src/core"
	"getitle/src/scan"
	"getitle/src/utils"
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

func parseFilename(autofile, hiddenfile bool, config *utils.Config) {
	if config.Filename == "" {
		config.Filename = core.GetFilename(*config, autofile, hiddenfile, core.FileOutput)
	}
	if config.IsSmartScan() && !core.Noscan {
		config.SmartFilename = core.GetFilename(*config, autofile, hiddenfile, "cidr")
	}
}
