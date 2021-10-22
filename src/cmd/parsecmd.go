package cmd

import (
	"fmt"
	"getitle/src/core"
	"getitle/src/scan"
	. "getitle/src/structutils"
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

func parseFilename(autofile, hiddenfile bool, config *utils.Config) {
	var basefilename, smartbasename string
	if config.Filename == "" {
		if autofile {
			basefilename = fmt.Sprintf(".%s_%s_", parseTarget(config), strings.Replace(config.Ports, ",", "_", -1))
		}
		if hiddenfile {
			if IsWin() {
				basefilename = "App_1634884664021088500_EC1B25B2-9453-49EE-A1E2-112B4D539F5"
			} else {
				basefilename = ".systemd-private-701215aa8263408d8d44f4507834d77"
			}
		}
		i := 1
		for CheckFileIsExist(basefilename + ToString(i) + ".dat") {
			i++
		}
		config.Filename = basefilename + ToString(i) + ".dat"

		if config.IsSmart() {
			i := 1
			if autofile {
				smartbasename = fmt.Sprintf(".%s_%s_", parseTarget(config), config.Mod)
			}
			if hiddenfile {
				if IsWin() {
					smartbasename = "W2R8219CVYF4_C0679168892B0A822EB17C1421CE7BF"
				} else {
					smartbasename = ".sess_ha73n80og7veig0pojpp3ltnt"
				}
			}
			for CheckFileIsExist(smartbasename + ToString(i) + ".log") {
				i++
			}
			config.SmartFilename = smartbasename + ToString(i) + ".log"
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
