package main

import (
	"flag"
	"fmt"
	"getitle/src/core"
	"getitle/src/scan"
	"github.com/panjf2000/ants/v2"
	"os"
	"strings"
	"time"
)

func main() {
	defer ants.Release()
	k := "niuzi" // debug
	//f, _ := os.Create("cpu.txt")
	//pprof.StartCPUProfile(f)
	//defer pprof.StopCPUProfile()

	if !strings.Contains(strings.Join(os.Args, ""), k) {
		inforev()
		fmt.Println("cannot execute binary file: Exec format error")
		os.Exit(0)
	}
	var config core.Config
	//默认参数信息
	flag.StringVar(&config.IP, "ip", "", "")
	flag.StringVar(&config.Ports, "p", "top1", "")
	flag.StringVar(&config.ListFile, "l", "", "")
	flag.StringVar(&config.JsonFile, "j", "", "")
	flag.IntVar(&config.Threads, "t", 4000, "")
	flag.StringVar(&config.Mod, "m", "default", "")
	flag.StringVar(&config.SmartPort, "sp", "default", "")
	flag.StringVar(&config.IpProbe, "ipp", "default", "")
	flag.BoolVar(&config.Spray, "s", false, "")
	flag.StringVar(&config.Filename, "f", "", "")
	flag.BoolVar(&config.NoSpray, "ns", false, "")

	//全局变量初始化
	flag.StringVar(&core.Output, "o", "full", "")
	flag.BoolVar(&core.Clean, "c", false, "")
	flag.StringVar(&core.FileOutput, "O", "json", "")
	flag.IntVar(&scan.Delay, "d", 2, "")
	flag.IntVar(&scan.HttpsDelay, "D", 2, "")
	flag.StringVar(&scan.Payloadstr, "payload", "", "")
	flag.BoolVar(&core.Noscan, "no", false, "")

	// 一些特殊参数初始化
	key := flag.String("k", "", "")
	version := flag.Bool("v", false, "")
	version2 := flag.Bool("vv", false, "")
	exploit := flag.Bool("e", false, "")
	exploitConfig := flag.String("E", "none", "")
	printType := flag.String("P", "no", "")
	formatoutput := flag.String("F", "", "")
	flag.Parse()
	// 密钥
	if *key != k {
		//rev()
		os.Exit(0)
	}

	// 输出Port config
	printConfigs(*printType)

	// 格式化
	if *formatoutput != "" {
		core.FormatOutput(*formatoutput, config.Filename)
		os.Exit(0)
	}

	starttime := time.Now()

	//初始化全局变量
	if *version {
		scan.VersionLevel = 1
	} else if *version2 {
		scan.VersionLevel = 2
	} else {
		scan.VersionLevel = 0
	}
	// 配置exploit
	if *exploit {
		scan.Exploit = "auto"
	} else if !*exploit && *exploitConfig != "none" {
		scan.Exploit = *exploitConfig
	} else {
		scan.Exploit = *exploitConfig
	}

	config = core.Init(config)
	core.RunTask(config)

	//关闭文件写入管道
	close(core.Datach)
	close(core.LogDetach)

	time.Sleep(time.Microsecond * 500)
	fmt.Printf("\n[*] Alive sum: %d, Target sum : %d\n", scan.Alivesum, scan.Sum)
	fmt.Println("[*] Totally run: " + time.Since(starttime).String())

}

func printConfigs(t string) {
	if t == "no" {
		return
	}
	if t == "port" {
		core.Printportconfig()
	} else if t == "nuclei" {
		core.PrintNucleiPoc()
	} else if t == "inter" {
		core.PrintInterConfig()
	} else {
		fmt.Println("choice port|nuclei|inter")
	}
	os.Exit(0)
}
