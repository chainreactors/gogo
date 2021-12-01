package core

import (
	"fmt"
	"getitle/src/scan"
	. "getitle/src/structutils"
	. "getitle/src/utils"
	"os"
	"strings"
)

var Clean bool
var Noscan bool

var InterConfig = map[string][]string{
	"10.0.0.0/8":     {"ss", "icmp", "1"},
	"172.16.0.0/12":  {"ss", "icmp", "1"},
	"192.168.0.0/16": {"s", "80", "all"},
	"100.100.0.0/16": {"s", "icmp", "all"},
	"200.200.0.0/16": {"s", "icmp", "all"},
	"169.254.0.0/16": {"s", "icmp", "all"},
	"168.254.0.0/16": {"s", "icmp", "all"},
}

func Init(config Config) Config {
	//println("*********  main 0.9.4 beta by Sangfor  *********")

	//if config.Mod != "default" && config.ListFile != "" {
	//	println("[-] error Smart scan config")
	//	os.Exit(0)
	//}
	config.Stdin = hasStdin()

	// check命令行参数
	checkCommand(config)

	// 初始化
	config.Exploit = scan.Exploit
	config.VerisonLevel = scan.VersionLevel

	//windows系统默认协程数为2000
	if config.Threads == 4000 { // if 默认线程
		if IsWin() {
			config.Threads = 1000
		} else if config.JsonFile != "" {
			config.Threads = 1000
		}
		if config.JsonFile != "" {
			config.Threads = 50
		}
	}

	// 初始化文件操作
	initFile(config)

	if config.ListFile != "" {
		// 如果从文件中读,初始化IP列表配置
		f, err := os.Open(config.ListFile)
		if err != nil {
			fmt.Println("[-] " + err.Error())
			os.Exit(0)
		}
		config.IPlist = loadFile(f)
	} else if config.JsonFile != "" {
		// 如果输入的json不为空,则从json中加载result,并返回结果
		taskresult, err := LoadResult(config.JsonFile)
		if err != nil {
			os.Exit(0)
		}
		config.Results = taskresult.Data
		return config
	} else if config.IP == "" {
		config.IPlist = loadFile(os.Stdin)
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

	// 初始化端口配置
	config.Portlist = portHandler(config.Ports)

	return config
}

func checkCommand(config Config) {
	// 一些命令行参数错误处理,如果check没过直接退出程序或输出警告
	if config.Mod == "ss" && config.ListFile != "" {
		fmt.Println("[-] error Smart scan can not use File input")
		os.Exit(0)
	}
	if config.JsonFile != "" {
		if config.Ports != "top1" {
			fmt.Println("[warn] json input can not config ports")
		}
		if config.Mod != "default" {
			fmt.Println("[warn] input json can not config scan Mod,default scanning")
		}
	}
	if config.IP == "" && config.ListFile == "" && config.JsonFile == "" && config.Mod != "a" && !config.Stdin { // 一些导致报错的参数组合
		fmt.Println("[-] cannot found target, please set -ip or -l or -j -or -a or stdin")
		os.Exit(0)
	}
}

func printTaskInfo(config Config, taskname string) {
	// 输出任务的基本信息

	fmt.Printf("[*] Current goroutines: %d, Version Level: %d,Exploit Target: %s, Spray Scan: %t\n", config.Threads, scan.VersionLevel, scan.Exploit, config.Spray)
	if config.JsonFile == "" {
		processLogln(fmt.Sprintf("[*] Start scan task %s ,total ports: %d , mod: %s", taskname, len(config.Portlist), config.Mod))
		// 输出端口信息
		if len(config.Portlist) > 500 {
			fmt.Println("[*] too much ports , only show top 500 ports: " + strings.Join(config.Portlist[:500], ",") + "......")
		} else {
			fmt.Println("[*] ports: " + strings.Join(config.Portlist, ","))
		}
		// 输出预估时间
		if config.Mod == "default" {
			processLogln(fmt.Sprintf("[*] Scan task time is about %d seconds", guessTime(config)))
		} else if config.IsSmart() {
			processLogln(fmt.Sprintf("[*] Smart scan task time is about %d seconds", guessSmarttime(config)))
		}
	} else {
		processLogln(fmt.Sprintf("[*] Start scan task %s ,total target: %d", taskname, len(config.Results)))
		processLogln(fmt.Sprintf("[*] Json scan task time is about %d seconds", (len(config.Results)/config.Threads)*4+4))
	}
}

func RunTask(config Config) {
	var taskname string
	if config.Mod == "a" {
		// 内网探测默认使用icmp扫描
		taskname = "preset internet IP addresses"
	} else {
		err := ipInit(&config)
		if err != nil {
			fmt.Println("[-] " + err.Error())
			fmt.Println("[-] init target failed!")
			os.Exit(0)
		}
		taskname = config.GetTargetName()
	}
	if taskname == "" {
		fmt.Println("[-] No Task")
		os.Exit(0)
	}

	// 如果指定端口超过100,则自动启用spray
	if len(config.Portlist) > 150 && !config.NoSpray {
		if config.IPlist == nil && getMask(config.IP) == 32 {
			config.Spray = false
		} else {
			config.Spray = true
		}
	}
	// 输出任务的基本信息
	printTaskInfo(config, taskname)

	switch config.Mod {
	case "default":
		StraightMod(config)
	case "a", "auto":
		autoScan(config)
	case "s", "f", "ss", "sc":
		mask := getMask(config.IP)
		if mask >= 24 {
			config.Mod = "default"
			StraightMod(config)
		} else {
			SmartMod(config)
		}
	default:
		StraightMod(config)
	}
}

func guessTime(config Config) int {
	ipcount := 0

	portcount := len(config.Portlist)
	if config.IPlist != nil {
		for _, ip := range config.IPlist {
			mask := getMask(ip)
			ipcount += countip(mask)
		}
	} else {
		mask := getMask(config.IP)
		ipcount = countip(mask)
	}
	return (portcount*ipcount/config.Threads)*4 + 4
}

func guessSmarttime(config Config) int {
	var spc, ippc int
	spc = len(config.SmartPortList)
	if config.IsSmart1() {
		ippc = 1
	} else {
		ippc = len(config.IpProbeList)
	}
	mask := getMask(config.IP)
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

func autoScan(config Config) {
	for cidr, st := range InterConfig {
		processLogln("[*] Spraying : " + cidr)
		SmartMod(createSmartTask(config, cidr, st))
	}
}

func createSmartTask(config Config, cidr string, c []string) Config {
	config.IP = cidr
	config.SmartPortList = portHandler(c[1])
	config.Mod = c[0]
	if c[2] != "all" {
		config.IpProbe = c[2]
		config.IpProbeList = Str2uintlist(c[2])
	}
	return config
}

func hasStdin() bool {
	stat, err := os.Stdin.Stat()
	if err != nil {
		return false
	}

	isPipedFromChrDev := (stat.Mode() & os.ModeCharDevice) == 0
	isPipedFromFIFO := (stat.Mode() & os.ModeNamedPipe) != 0

	return isPipedFromChrDev || isPipedFromFIFO
}
