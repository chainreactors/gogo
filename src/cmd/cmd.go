package cmd

import (
	"flag"
	"fmt"
	. "getitle/src/core"
	. "getitle/src/scan"
	. "getitle/src/structutils"
	. "getitle/src/utils"
	"github.com/panjf2000/ants/v2"
	"os"
	"regexp"
	"strings"
	"time"
)

func CMD(k string) {
	defer ants.Release()
	connected = checkconn()
	if !strings.Contains(strings.Join(os.Args, ""), k) {
		inforev()
	}
	var config Config
	//默认参数信息
	flag.StringVar(&config.IP, "ip", "", "")
	flag.StringVar(&config.Ports, "p", "top1", "")
	flag.StringVar(&config.ListFile, "l", "", "")
	flag.StringVar(&config.JsonFile, "j", "", "")
	flag.BoolVar(&config.IsListInput, "L", false, "")
	flag.BoolVar(&config.IsJsonInput, "J", false, "")
	flag.IntVar(&config.Threads, "t", 4000, "")
	flag.StringVar(&config.Mod, "m", "default", "")
	flag.StringVar(&config.SmartPort, "sp", "default", "")
	flag.StringVar(&config.IpProbe, "ipp", "default", "")
	flag.BoolVar(&config.Spray, "s", false, "")
	flag.StringVar(&config.Filename, "f", "", "")
	flag.BoolVar(&config.NoSpray, "ns", false, "")

	//全局变量初始化
	flag.StringVar(&Opt.Output, "o", "full", "")
	flag.BoolVar(&Opt.Clean, "c", false, "")
	flag.StringVar(&Opt.FileOutput, "O", "json", "")
	flag.BoolVar(&Opt.Noscan, "no", false, "")
	flag.BoolVar(&Opt.Quiet, "q", false, "")
	flag.IntVar(&RunOpt.Delay, "d", 2, "")
	flag.IntVar(&RunOpt.HttpsDelay, "D", 2, "")
	flag.StringVar(&RunOpt.Payloadstr, "payload", "", "")

	// 一些特殊参数初始化
	key := flag.String("k", "", "")
	version := flag.Bool("v", false, "")
	version2 := flag.Bool("vv", false, "")
	exploit := flag.Bool("e", false, "")
	exploitConfig := flag.String("E", "none", "")
	printType := flag.String("P", "", "")
	resultfilename := flag.String("F", "", "")
	autofile := flag.Bool("af", false, "")
	hiddenfile := flag.Bool("hf", false, "")
	noup := flag.Bool("nu", false, "")
	uploadfile := flag.String("uf", "", "")
	pocfile := flag.String("ef", "", "")
	compress := flag.Bool("C", false, "")

	flag.Parse()
	// 密钥
	if *key != k {
		//rev()
		os.Exit(0)
	}

	// 输出 config
	if *printType != "" {
		printConfigs(*printType)
		os.Exit(0)
	}

	// 格式化
	if *resultfilename != "" {
		FormatOutput(*resultfilename, config.Filename, *autofile)
		os.Exit(0)
	}

	if *uploadfile != "" {
		// 指定上传文件
		uploadfiles([]string{*uploadfile})
		os.Exit(0)
	}

	// 加载配置文件中的全局变量
	configloader(*pocfile)

	// 加载命令行中的参数配置
	parseVersion(*version, *version2)
	parseExploit(*exploit, *exploitConfig)
	parseFilename(*autofile, *hiddenfile, &config)

	if *compress {
		Opt.Compress = !Opt.Compress
	}

	starttime := time.Now()
	config = Init(config)
	RunTask(config)

	//关闭文件写入管道
	close(Opt.DataCh)
	close(Opt.LogDataCh)

	time.Sleep(500 * time.Microsecond)

	if *hiddenfile {
		Chtime(config.Filename)
		if config.SmartFilename != "" {
			Chtime(config.SmartFilename)
		}
	}
	time.Sleep(time.Microsecond * 500)

	// 任务统计
	ConsoleLog(fmt.Sprintf("\n[*] Alive sum: %d, Target sum : %d", Opt.AliveSum, RunOpt.Sum))
	ConsoleLog("[*] Totally run: " + time.Since(starttime).String())

	var filenamelog string
	// 输出
	if config.Filename != "" {
		filenamelog = fmt.Sprintf("[*] Results filename: %s, ", config.Filename)
		if config.SmartFilename != "" {
			filenamelog += "Smartscan result filename: " + config.SmartFilename
		}
		ConsoleLog(filenamelog)
	}

	// 扫描结果文件自动上传
	if connected && !*noup && config.Filename != "" { // 如果出网则自动上传结果到云服务器
		uploadfiles([]string{config.Filename, config.SmartFilename})
	}
}

func printConfigs(t string) {
	if t == "port" {
		Printportconfig()
	} else if t == "nuclei" {
		PrintNucleiPoc()
	} else if t == "inter" {
		PrintInterConfig()
	} else {
		fmt.Println("choice port|nuclei|inter")
	}
}

func configloader(pocfile string) {
	Compiled = make(map[string][]regexp.Regexp)
	Mmh3fingers, Md5fingers = LoadHashFinger()
	Tcpfingers = LoadFingers("tcp")
	Httpfingers = LoadFingers("http")
	Tagmap, Namemap, Portmap = LoadPortConfig()
	CommonCompiled = map[string]regexp.Regexp{
		"title":     CompileRegexp("(?Uis)<title>(.*)</title>"),
		"server":    CompileRegexp("(?i)Server: ([\x20-\x7e]+)"),
		"xpb":       CompileRegexp("(?i)X-Powered-By: ([\x20-\x7e]+)"),
		"sessionid": CompileRegexp("(?i) (.*SESS.*?ID)"),
	}
	LoadNuclei(pocfile)
}
