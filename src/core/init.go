package core

import (
	"errors"
	"fmt"
	. "getitle/src/pkg"
	. "getitle/src/scan"
	. "getitle/src/utils"
	"os"
	"strings"
)

var Opt = Options{
	AliveSum: 0,
	Noscan:   false,
	Compress: true,
}

func InitConfig(config *Config) *Config {
	err := validate(config)
	if err != nil {
		Panic("[-] " + err.Error())
	}
	// 初始化
	config.Exploit = RunOpt.Exploit
	config.VersionLevel = RunOpt.VersionLevel

	if config.Threads == 0 { // if 默认线程
		config.Threads = 4000
		if Win {
			//windows系统默认协程数为1000
			config.Threads = 1000
		} else {
			// linux系统判断fd限制, 如果-t 大于fd限制,则将-t 设置到fd-100
			if fdlimit := GetFdLimit(); config.Threads > fdlimit {
				Log.Warn(fmt.Sprintf("System fd limit: %d , Please exec 'ulimit -n 65535'", fdlimit))
				Log.Warn(fmt.Sprintf("System fd limit: %d , Please exec 'ulimit -n 65535'", fdlimit))
				Log.Warn(fmt.Sprintf("System fd limit: %d , Please exec 'ulimit -n 65535'", fdlimit))
				Log.Warn(fmt.Sprintf("Now set threads to %d", fdlimit-100))
				config.Threads = fdlimit - 100
			}
		}
		if config.JsonFile != "" {
			config.Threads = 50
		}
	}

	var file *os.File
	if config.ListFile != "" {
		file = Open(config.ListFile)
	} else if config.JsonFile != "" {
		file = Open(config.JsonFile)
	} else if HasStdin() {
		file = os.Stdin
	}

	// 初始化文件操作
	err = initFile(config)
	if err != nil {
		Panic("[-] " + err.Error())
	}

	if config.ListFile != "" || config.IsListInput {
		// 如果从文件中读,初始化IP列表配置
		config.IPlist = strings.Split(string(LoadFile(file)), "\n")
	} else if config.JsonFile != "" || config.IsJsonInput {
		// 如果输入的json不为空,则从json中加载result,并返回结果
		data := LoadResultFile(file)
		switch data.(type) {
		case Results:
			config.Results = data.(Results)
		case ResultsData:
			config.Results = data.(ResultsData).Data
		case SmartData:
			config.IPlist = data.(SmartData).Data
		default:
			Panic("[-] not support result, maybe use -l")
		}
	}

	initIP(config)
	// 初始化端口配置
	config.Portlist = portHandler(config.Ports)

	// 如果指定端口超过100,则自动启用spray
	if len(config.Portlist) > 150 && !config.NoSpray {
		if config.IPlist == nil && getMask(config.IP) == 32 {
			config.PortSpray = false
		} else {
			config.PortSpray = true
		}
	}

	// 初始化启发式扫描的端口探针
	if config.SmartPort != "default" {
		config.SmartPortList = portHandler(config.SmartPort)
	} else {
		if config.Mod == "s" {
			config.SmartPortList = []string{"80"}
		} else if SliceContains([]string{"ss", "sc", "f"}, config.Mod) {
			config.SmartPortList = []string{"icmp"}
		}
	}

	// 初始化ss模式ip探针,默认ss默认只探测ip为1的c段,可以通过-ipp参数指定,例如-ipp 1,254,253
	if config.IpProbe != "default" {
		config.IpProbeList = Str2uintlist(config.IpProbe)
	} else {
		config.IpProbeList = []uint{1}
	}

	if config.ExcludeIPs != "" {
		config.ExcludeMap = make(map[uint]bool)
		for _, ip := range strings.Split(config.ExcludeIPs, ",") {
			start, end := getIpRange(cidrFormat(ip))
			for i := start; i <= end; i++ {
				config.ExcludeMap[i] = true
			}
		}
	}

	// 初始已完成,输出任务基本信息
	taskname := config.GetTargetName()
	// 输出任务的基本信息
	printTaskInfo(config, taskname)
	return config
}

func validate(config *Config) error {
	// 一些命令行参数错误处理,如果check没过直接退出程序或输出警告
	//if config.Mod == "ss" && config.ListFile != "" {
	//	fmt.Println("[-] error Smart . can not use File input")
	//	os.Exit(0)
	//}
	var err error
	if config.JsonFile != "" {
		if config.Ports != "top1" {
			Log.Warn("json input can not config ports")
		}
		if config.Mod != "default" {
			Log.Warn("input json can not config . Mod,default scanning")
		}
	}

	if config.IP == "" && config.ListFile == "" && config.JsonFile == "" && config.Mod != "a" && !HasStdin() { // 一些导致报错的参数组合
		err = errors.New("cannot found target, please set -ip or -l or -j -or -a or stdin")
	}

	if config.JsonFile != "" && config.ListFile != "" {
		err = errors.New("cannot set -j and -l flags at same time")
	}

	if !HasPingPriv() && (strings.Contains(config.Ports, "icmp") || strings.Contains(config.Ports, "ping") || SliceContains(config.AliveSprayMod, "icmp")) {
		Log.Warn("current user is not root, icmp scan not work")
	}

	if !Win && Root && (strings.Contains(config.Ports, "arp") || SliceContains(config.AliveSprayMod, "arp")) {
		Log.Warn("current user is not root, arp scan maybe not work")
	}
	if Win && (strings.Contains(config.Ports, "arp") || SliceContains(config.AliveSprayMod, "arp")) {
		Log.Warn("windows not support arp scan, skip all arp scan task")
	}
	return err
}

func printTaskInfo(config *Config, taskname string) {
	// 输出任务的基本信息

	Log.Logging(fmt.Sprintf("[*] Current goroutines: %d, Version Level: %d,Exploit Target: %s, PortSpray Scan: %t", config.Threads, RunOpt.VersionLevel, RunOpt.Exploit, config.PortSpray))
	if config.JsonFile == "" {
		Log.Logging(fmt.Sprintf("[*] Starting task %s ,total ports: %d , mod: %s", taskname, len(config.Portlist), config.Mod))
		// 输出端口信息
		if len(config.Portlist) > 500 {
			Log.Logging("[*] too much ports , only show top 500 ports: " + strings.Join(config.Portlist[:500], ",") + "......")
		} else {
			Log.Logging("[*] ports: " + strings.Join(config.Portlist, ","))
		}
	} else {
		Log.Logging(fmt.Sprintf("[*] Starting results task: %s ,total target: %d", taskname, len(config.Results)))
		//progressLog(fmt.Sprintf("[*] Json . task time is about %d seconds", (len(config.Results)/config.Threads)*4+4))
	}
}

func RunTask(config Config) {
	switch config.Mod {
	case "default":
		createDefaultScan(config)
	//case "a", "auto":
	//	autoScan(config)
	case "s", "f", "ss", "sc":
		if config.IPlist != nil {
			for _, ip := range config.IPlist {
				Log.Logging("[*] Spraying : " + ip)
				createSmartScan(ip, config)
			}
		} else {
			createSmartScan(config.IP, config)
		}
	default:
		createDefaultScan(config)
	}
}

func guessTime(targets interface{}, portcount, thread int) int {
	ipcount := 0

	switch targets.(type) {
	case []string:
		for _, ip := range targets.([]string) {
			mask := getMask(ip)
			ipcount += countip(mask)
		}
	case Results:
		ipcount = len(targets.(Results))
		portcount = 1
	default:
		mask := getMask(targets.(string))
		ipcount = countip(mask)
	}

	return (portcount*ipcount/thread)*4 + 4
}

func guessSmarttime(target string, config Config) int {
	var spc, ippc int
	var mask int
	spc = len(config.SmartPortList)
	if config.IsBSmart() {
		ippc = 1
	} else {
		ippc = len(config.IpProbeList)
	}
	mask = getMask(target)

	var count int
	if config.Mod == "s" || config.Mod == "sb" {
		count = 2 << uint((32-mask)-1)
	} else {
		count = 2 << uint((32-mask)-9)
	}

	return ((spc*ippc*count)/(config.Threads)*2 + 2)
}

func countip(mask int) int {
	count := 0
	if mask == 32 {
		count++
	} else {
		count += 2 << (31 - uint(mask))
	}
	return count
}

//func autoScan(config Config) {
//	for cidr, st := range InterConfig {
//		Log.Logging("[*] Spraying : " + cidr)
//		createAutoTask(config, cidr, st)
//	}
//}

//func createAutoTask(config Config, cidr string, c []string) {
//	config.SmartPortList = portHandler(c[1])
//	config.Mod = c[0]
//	if c[2] != "all" {
//		config.IpProbe = c[2]
//		config.IpProbeList = Str2uintlist(c[2])
//	}
//	SmartMod(cidr, config)
//}

func createSmartScan(ip string, config Config) {
	mask := getMask(ip)
	if mask > 24 {
		config.Mod = "default"
		DefaultMod(ip, config)
	} else {
		SmartMod(ip, config)
	}
}

func createDefaultScan(config Config) {
	if config.Results != nil {
		DefaultMod(config.Results, config)
	} else {
		if config.HasAlivedScan() {
			if config.IPlist != nil {
				AliveMod(config.IPlist, config)
			} else if config.IP != "" {
				AliveMod(config.IP, config)
			}
		} else {
			if config.IPlist != nil {
				DefaultMod(config.IPlist, config)
			} else if config.IP != "" {
				DefaultMod(config.IP, config)
			}
		}
	}
}
