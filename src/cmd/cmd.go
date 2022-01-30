package cmd

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	. "getitle/src/core"
	. "getitle/src/scan"
	. "getitle/src/structutils"
	. "getitle/src/utils"

	"github.com/panjf2000/ants/v2"
)

var ver = ""
var k = "ybb"

func CMD() {
	defer ants.Release()
	connected = checkconn()
	if !strings.Contains(strings.Join(os.Args, ""), k) {
		inforev()
	}
	var config Config
	var filters, payloads, extracts arrayFlags
	//默认参数信息
	// INPUT
	flag.StringVar(&config.IP, "ip", "", "")
	flag.StringVar(&config.Ports, "p", "top1", "")
	flag.StringVar(&config.ListFile, "l", "", "")
	flag.StringVar(&config.JsonFile, "j", "", "")
	flag.BoolVar(&config.IsListInput, "L", false, "")
	flag.BoolVar(&config.IsJsonInput, "J", false, "")

	// SMART
	flag.StringVar(&config.SmartPort, "sp", "default", "")
	flag.StringVar(&config.IpProbe, "ipp", "default", "")
	flag.BoolVar(&config.NoSpray, "ns", false, "")
	flag.BoolVar(&Opt.Noscan, "no", false, "")

	// OUTPUT
	flag.StringVar(&config.Filename, "f", "", "")
	flag.StringVar(&config.ExcludeIPs, "eip", "", "")
	flag.StringVar(&Opt.Output, "o", "full", "")
	flag.BoolVar(&Opt.Clean, "c", false, "")
	flag.StringVar(&Opt.FileOutput, "O", "json", "")
	flag.BoolVar(&Opt.Quiet, "q", false, "")
	flag.Var(&filters, "filter", "")
	resultfilename := flag.String("F", "", "")
	autofile := flag.Bool("af", false, "")
	hiddenfile := flag.Bool("hf", false, "")
	compress := flag.Bool("C", false, "")

	// CONFIG
	flag.IntVar(&config.Threads, "t", 0, "")
	flag.StringVar(&config.Mod, "m", "default", "")
	flag.BoolVar(&config.Spray, "s", false, "")
	flag.BoolVar(&config.Ping, "ping", false, "")
	flag.BoolVar(&Opt.Debug, "debug", false, "")
	flag.IntVar(&RunOpt.Delay, "d", 2, "")
	flag.IntVar(&RunOpt.HttpsDelay, "D", 2, "")
	flag.StringVar(&RunOpt.Payloadstr, "suffix", "", "")
	flag.Var(&payloads, "payload", "")
	flag.Var(&extracts, "extract", "")
	extractStr := flag.String("extracts", "", "")
	version := flag.Bool("v", false, "")
	version2 := flag.Bool("vv", false, "")
	exploit := flag.Bool("e", false, "")
	exploitConfig := flag.String("E", "none", "")
	pocfile := flag.String("ef", "", "")

	// OTHER
	key := flag.String("k", "", "")
	printType := flag.String("P", "", "")
	noup := flag.Bool("nu", false, "")
	uploadfile := flag.String("uf", "", "")
	gtversion := flag.Bool("version", false, "")

	flag.Usage = func() { exit() }
	flag.Parse()
	// 密钥
	if *key != k {
		//rev()
		exit()
	}
	if *gtversion {
		fmt.Println(ver)
		os.Exit(0)
	}

	// 输出 config
	if *printType != "" {
		printConfigs(*printType)
		os.Exit(0)
	}

	// 格式化
	if *resultfilename != "" {
		FormatOutput(*resultfilename, config.Filename, *autofile, filters)
		os.Exit(0)
	}

	if *compress {
		Opt.Compress = !Opt.Compress
	}

	if *uploadfile != "" {
		// 指定上传文件
		uploadfiles([]string{*uploadfile})
		os.Exit(0)
	}

	// 加载配置文件中的全局变量
	configloader()
	nucleiLoader(*pocfile, payloads)
	// 解析命令行中的参数配置
	parseVersion(*version, *version2)
	parseExploit(*exploit, *exploitConfig)
	parseFilename(*autofile, *hiddenfile, &config)
	parseExtractors(extracts, *extractStr)

	starttime := time.Now()
	// 初始化任务
	config = Init(config)
	RunTask(config) // 运行

	time.Sleep(200 * time.Microsecond)

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
	// 输出文件名
	if config.Filename != "" {
		filenamelog = fmt.Sprintf("[*] Results filename: %s , ", config.Filename)
		if config.SmartFilename != "" {
			filenamelog += "Smartscan result filename: " + config.SmartFilename + " , "
		}
		if config.PingFilename != "" {
			filenamelog += "Pingscan result filename: " + config.PingFilename
		}
		if IsExist(config.Filename + "_extract") {
			filenamelog += "extractor result filename: " + config.Filename + "_extractor"
		}
		ConsoleLog(filenamelog)
	}

	// 扫描结果文件自动上传
	if connected && !*noup && config.Filename != "" { // 如果出网则自动上传结果到云服务器
		uploadfiles([]string{config.Filename, config.SmartFilename})
	}
}

type Value interface {
	String() string
	Set(string) error
}

type arrayFlags []string

// Value ...
func (i *arrayFlags) String() string {
	return fmt.Sprint(*i)
}

// Set 方法是flag.Value接口, 设置flag Value的方法.
// 通过多个flag指定的值， 所以我们追加到最终的数组上.
func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}
