package cmd

import (
	"fmt"
	. "getitle/src/core"
	. "getitle/src/pkg"
	. "getitle/src/scan"
	. "getitle/src/utils"
	"net"
	"os"
	"path"
	"regexp"
	"strings"
	"time"
)

func NewRunner() *Runner {
	return &Runner{
		config: Config{},
	}
}

type Runner struct {
	Ports        string
	Version      bool // version level1
	Version2     bool // version level2
	Exploit      bool // 启用漏洞扫描
	NoUpload     bool // 关闭文件回传
	Compress     bool // 启用压缩
	Clean        bool // 是否开启命令行输出扫描结果
	Quiet        bool // 是否开启命令行输出日志
	AutoFile     bool // 自动生成格式化文件名
	HiddenFile   bool // 启用自动隐藏文件
	Ping         bool
	Arp          bool
	FormatOutput string // 待格式化文件名
	filters      arrayFlags
	payloads     arrayFlags
	extract      arrayFlags
	extracts     string
	ExploitName  string // 指定漏扫poc名字
	ExploitFile  string // 指定漏扫文件
	Printer      string // 输出特定的预设
	UploadFile   string // 上传特定的文件名
	WorkFlowName string
	Ver          bool // 输出版本号
	NoScan       bool
	IsWorkFlow   bool
	Debug        bool
	iface        string
	start        time.Time
	config       Config
}

func (r *Runner) preInit() bool {
	// 初始化日志工具
	Log = NewLogger(r.Quiet)
	if r.Debug {
		Opt.Debug = true
		RunOpt.Debug = true
	}
	// 一些特殊的分支, 不继续先后执行
	if r.Ver {
		fmt.Println(ver)
		return false
	}
	if r.FormatOutput != "" {
		FormatOutput(r.FormatOutput, r.config.Filename, r.AutoFile, r.filters)
		return false
	}
	// 输出 config
	if r.Printer != "" {
		printConfigs(r.Printer)
		return false
	}

	if r.UploadFile != "" {
		// 指定上传文件
		uploadfiles(strings.Split(r.UploadFile, ","))
		return false
	}
	return true
}

func (r *Runner) init() {
	// 初始化各种全局变量
	// 初始化指纹优先级
	if r.Version {
		RunOpt.VersionLevel = 1
	} else if r.Version2 {
		RunOpt.VersionLevel = 2
	} else {
		RunOpt.VersionLevel = 0
	}

	// 初始化漏洞
	if r.Exploit {
		RunOpt.Exploit = "auto"
	} else {
		RunOpt.Exploit = r.ExploitName
	}

	if r.NoScan {
		Opt.Noscan = r.NoScan
	}

	if r.Compress {
		Opt.Compress = !Opt.Compress
	}

	if r.Clean {
		Log.Clean = !Log.Clean
	}

	if !Win {
		if r.iface == "eth0" {
			Log.Warn("no interface name input, use default interface name: eth0")
		}
		var err error
		RunOpt.Interface, err = net.InterfaceByName(r.iface)
		if err != nil {
			Log.Warn("interface error, " + err.Error())
			Log.Warn("interface error, " + err.Error())
			Log.Warn("interface error, " + err.Error())
		}
	}

	if r.extracts != "" {
		exts := strings.Split(r.extracts, ",")
		for _, extract := range exts {
			if reg, ok := PresetExtracts[extract]; ok {
				Extractors[extract] = reg
			}
		}
	}
	for _, extract := range r.extract {
		if reg, ok := PresetExtracts[extract]; ok {
			Extractors[extract] = reg
		} else {
			Extractors[extract] = CompileRegexp(extract)
		}
	}

	// 加载配置文件中的全局变量
	configLoader()
	nucleiLoader(r.ExploitFile, r.payloads)
	r.start = time.Now()
}

func (r *Runner) prepareConfig(config Config) *Config {
	if r.Ports == "" {
		config.Ports = "top1"
	} else {
		config.Ports = r.Ports
	}

	if r.Arp {
		config.AliveSprayMod = append(config.AliveSprayMod, "arp")
	}
	if r.Ping {
		config.AliveSprayMod = append(config.AliveSprayMod, "icmp")
	}

	if config.Filename == "" {
		config.Filename = GetFilename(&config, r.AutoFile, r.HiddenFile, Opt.FilePath, Opt.FileOutput)
	} else {
		config.Filename = path.Join(Opt.FilePath, config.Filename)
	}

	if config.IsSmartScan() && !Opt.Noscan {
		config.SmartFilename = GetFilename(&config, r.AutoFile, r.HiddenFile, Opt.FilePath, "cidr")
	}

	if config.HasAlivedScan() {
		config.PingFilename = GetFilename(&config, r.AutoFile, r.HiddenFile, Opt.FilePath, "alived")
	}
	return &config
}

func (r *Runner) run() {
	if r.WorkFlowName == "" && !r.IsWorkFlow {
		r.runWithCMD()
	} else {
		var workflowMap = WorkflowMap{}
		if r.IsWorkFlow {
			workflowMap["tmp"] = ParseWorkflowsFromInput(LoadFile(os.Stdin))
			r.WorkFlowName = "tmp"
		} else if IsExist(r.WorkFlowName) {
			workflowMap["tmp"] = ParseWorkflowsFromInput(LoadFile(Open(r.WorkFlowName)))
			r.WorkFlowName = "tmp"
		} else {
			workflowMap = LoadWorkFlow()
		}
		r.runWithWorkFlow(workflowMap)
	}
}

func (r *Runner) runWithCMD() {
	config := r.prepareConfig(r.config)
	RunTask(*InitConfig(config)) // 运行
	r.close(config)
}

func (r *Runner) runWithWorkFlow(workflowMap WorkflowMap) {
	if workflows := workflowMap.Choice(r.WorkFlowName); len(workflows) > 0 {
		for _, workflow := range workflows {
			Log.Logging("\n[*] workflow " + workflow.Name + " starting")
			// 文件名要在config初始化之前操作
			if r.config.Filename != "" {
				workflow.File = r.config.Filename
			} else if r.AutoFile {
				workflow.File = "auto"
			} else if r.HiddenFile {
				workflow.File = "hidden"
			}
			if Opt.FilePath != "" {
				workflow.Path = Opt.FilePath
			}

			config := workflow.PrepareConfig()
			// 一些workflow的参数, 允许被命令行参数覆盖
			if r.config.IP != "" {
				config.IP = r.config.IP
			}

			if r.config.ListFile != "" {
				config.ListFile = r.config.ListFile
			}

			if r.Ports != "" {
				config.Ports = r.Ports
			}

			if r.config.Threads != 0 {
				config.Threads = r.config.Threads
			}

			if r.config.SmartPort != "default" {
				config.SmartPort = r.config.SmartPort
			}

			if r.config.IpProbe != "default" {
				config.IpProbe = r.config.IpProbe
			}

			// 全局变量的处理
			if !r.NoScan {
				Opt.Noscan = workflow.NoScan
			}
			if r.Version {
				RunOpt.VersionLevel = 1
			} else {
				RunOpt.VersionLevel = workflow.Version
			}

			if RunOpt.Exploit != "none" {
				if r.Exploit {
					RunOpt.Exploit = "auto"
				} else {
					RunOpt.Exploit = r.ExploitName
				}
			} else {
				RunOpt.Exploit = workflow.Exploit
			}

			config = InitConfig(config)
			RunTask(*config) // 运行
			r.close(config)
			r.resetGlobals()
		}
	} else {
		Fatal("not fount workflow " + r.WorkFlowName)
	}
}

func (r *Runner) close(config *Config) {
	Opt.Close()                        // 关闭result与extract写入管道
	time.Sleep(time.Microsecond * 200) // 因为是异步的, 等待文件最后处理完成
	if r.HiddenFile {
		Chtime(config.Filename)
		if config.SmartFilename != "" {
			Chtime(config.SmartFilename)
		}
	}

	// 任务统计
	Log.Important(fmt.Sprintf("Alive sum: %d, Target sum : %d", Opt.AliveSum, RunOpt.Sum))
	Log.Important("Totally run: " + time.Since(r.start).String())

	var filenamelog string
	// 输出文件名
	if config.Filename != "" {
		filenamelog = fmt.Sprintf("Results filename: %s , ", config.Filename)
		if config.SmartFilename != "" {
			filenamelog += "Smartscan result filename: " + config.SmartFilename + " , "
		}
		if config.PingFilename != "" {
			filenamelog += "Pingscan result filename: " + config.PingFilename
		}
		if IsExist(config.Filename + "_extract") {
			filenamelog += "extractor result filename: " + config.Filename + "_extract"
		}
		Log.Important(filenamelog)
	}

	// 扫描结果文件自动上传
	if connected && !r.NoUpload && config.Filename != "" { // 如果出网则自动上传结果到云服务器
		uploadfiles([]string{config.Filename, config.SmartFilename})
	}
}

func (r *Runner) resetGlobals() {
	Opt.Noscan = false
	RunOpt.Exploit = "none"
	RunOpt.VersionLevel = 0
}

func printConfigs(t string) {
	if t == "port" {
		TagMap, NameMap, PortMap = LoadPortConfig()
		Printportconfig()
	} else if t == "nuclei" {
		nucleiLoader("", arrayFlags{})
		PrintNucleiPoc()
	} else if t == "workflow" {
		PrintWorkflow()
	} else if t == "extract" {
		PrintExtract()
	} else {
		fmt.Println("choice port|nuclei|workflow|extract")
	}
}

func nucleiLoader(pocfile string, payloads arrayFlags) {
	ExecuterOptions = ParserCmdPayload(payloads)
	TemplateMap = LoadNuclei(pocfile)
}

func configLoader() {
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
