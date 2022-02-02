package cmd

import (
	"fmt"
	. "getitle/src/core"
	. "getitle/src/scan"
	. "getitle/src/structutils"
	. "getitle/src/utils"
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
	Version      bool   // version level1
	Version2     bool   // version level2
	Exploit      bool   // 启用漏洞扫描
	NoUpload     bool   // 关闭文件回传
	Compress     bool   // 启用压缩
	Clean        bool   // 是否开启命令行输出扫描结果
	Quiet        bool   // 是否开启命令行输出日志
	AutoFile     bool   // 自动生成格式化文件名
	HiddenFile   bool   // 启用自动隐藏文件
	FormatOutput string // 待格式化文件名
	filters      arrayFlags
	payloads     arrayFlags
	extract      arrayFlags
	extracts     string
	ExploitName  string // 指定漏扫poc名字
	ExploitFile  string // 指定漏扫文件
	Printer      string // 输出特定的预设
	UploadFile   string // 上传特定的文件名
	Ver          bool   // 输出版本号
	start        time.Time
	config       Config
}

func (r *Runner) preInit() bool {
	// 初始化日志工具
	Log = NewLogger(r.Quiet)
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

	if r.Compress {
		Opt.Compress = !Opt.Compress
	}
	if r.Clean {
		Log.Clean = !Log.Clean
	}

	if r.config.Filename == "" {
		r.config.Filename = GetFilename(r.config, r.AutoFile, r.HiddenFile, Opt.FileOutput)
	} else {
		path.Join(Opt.FilePath, r.config.Filename)
	}

	if r.config.IsSmartScan() && !Opt.Noscan {
		r.config.SmartFilename = GetFilename(r.config, r.AutoFile, r.HiddenFile, "cidr")
	}

	if r.config.Ping {
		r.config.PingFilename = GetFilename(r.config, r.AutoFile, r.HiddenFile, "ping")
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
	configloader()
	nucleiLoader(r.ExploitFile, r.payloads)
	r.start = time.Now()
}

func (r *Runner) close() {
	if r.HiddenFile {
		Chtime(r.config.Filename)
		if r.config.SmartFilename != "" {
			Chtime(r.config.SmartFilename)
		}
	}

	// 任务统计
	Log.Important(fmt.Sprintf("Alive sum: %d, Target sum : %d", Opt.AliveSum, RunOpt.Sum))
	Log.Important("Totally run: " + time.Since(r.start).String())

	var filenamelog string
	// 输出文件名
	if r.config.Filename != "" {
		filenamelog = fmt.Sprintf("Results filename: %s , ", r.config.Filename)
		if r.config.SmartFilename != "" {
			filenamelog += "Smartscan result filename: " + r.config.SmartFilename + " , "
		}
		if r.config.PingFilename != "" {
			filenamelog += "Pingscan result filename: " + r.config.PingFilename
		}
		if IsExist(r.config.Filename + "_extract") {
			filenamelog += "extractor result filename: " + r.config.Filename + "_extractor"
		}
		Log.Important(filenamelog)
	}

	// 扫描结果文件自动上传
	if connected && !r.NoUpload && r.config.Filename != "" { // 如果出网则自动上传结果到云服务器
		uploadfiles([]string{r.config.Filename, r.config.SmartFilename})
	}
}
func printConfigs(t string) {
	if t == "port" {
		TagMap, NameMap, PortMap = LoadPortConfig()
		Printportconfig()
	} else if t == "nuclei" {
		LoadNuclei("")
		PrintNucleiPoc()
	} else if t == "inter" {
		PrintInterConfig()
	} else {
		fmt.Println("choice port|nuclei|inter")
	}
}

func nucleiLoader(pocfile string, payloads arrayFlags) {
	ExecuterOptions = ParserCmdPayload(payloads)
	TemplateMap = LoadNuclei(pocfile)
}

func configloader() {
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
