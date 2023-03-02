package core

import (
	"fmt"
	"github.com/chainreactors/files"
	. "github.com/chainreactors/gogo/v2/internal/plugin"
	. "github.com/chainreactors/gogo/v2/pkg"
	"github.com/chainreactors/logs"
	neuhttp "github.com/chainreactors/neutron/protocols/http"
	"github.com/chainreactors/parsers"
	"github.com/chainreactors/parsers/iutils"
	"golang.org/x/net/proxy"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

func NewRunner() *Runner {
	return &Runner{
		Config: Config{},
	}
}

var ver = ""

type Runner struct {
	MiscOption    `group:"Miscellaneous Options"`
	InputOption   `group:"Input Options"`
	OutputOption  `group:"Output Options"`
	SmartOption   `group:"Smart Options"`
	AdvanceOption `group:"Advance Options"`
	ConfigOption  `group:"Configuration Options"`

	start  time.Time
	Config Config
}

func (r *Runner) Prepare() bool {
	// 初始化日志工具
	if r.Quiet {
		logs.Log = logs.NewLogger(10, true)
	} else {
		if r.Debug {
			logs.Log = logs.NewLogger(logs.Debug, false)
		}
		logs.Log.LogFileName = ".sock.lock"
		logs.Log.Init()
	}

	RunOpt = RunnerOpts{
		Delay:      r.Delay,
		HttpsDelay: r.HttpsDelay,
		//SuffixStr:  r.SuffixStr,
	}
	Opt.PluginDebug = r.PluginDebug
	parsers.NoGuess = r.NoGuess
	files.Key = []byte(r.Key)

	// 一些特殊的分支, 这些分支将会直接退出程序
	if r.Ver {
		fmt.Println(ver)
		return false
	}

	r.PrepareConfig()
	if r.FormatterFilename != "" {
		FormatOutput(r.FormatterFilename, r.Config.Filename, r.Config.Outputf, r.Config.Filenamef, r.Filters, r.FilterOr)
		return false
	}
	// 输出 Config
	if r.Printer != "" {
		printConfigs(r.Printer)
		return false
	}

	if r.Proxy != "" {
		uri, err := url.Parse(r.Proxy)
		if err == nil {
			ProxyUrl = uri
			Proxy = http.ProxyURL(uri)
			neuhttp.Proxy = Proxy
			ProxyDialTimeout = func(network, address string, duration time.Duration) (net.Conn, error) {
				forward := &net.Dialer{Timeout: duration}
				dial, err := proxy.FromURL(uri, forward)
				if err != nil {
					return nil, err
				}
				conn, err := dial.Dial(network, address)
				if err != nil {
					return nil, err
				}
				return conn, nil
			}

		} else {
			logs.Log.Warnf("parse proxy error %s, skip proxy!", err.Error())
		}
	}
	return true
}

func (r *Runner) Init() {
	// 初始化各种全局变量
	// 初始化指纹优先级
	if r.Verbose {
		RunOpt.VersionLevel = 1
		//} else if r.Version2 {
		//	RunOpt.VersionLevel = 2
	} else {
		RunOpt.VersionLevel = 0
	}

	// 初始化漏洞
	if r.ExploitName != "" {
		RunOpt.Exploit = r.ExploitName
	} else if r.Exploit {
		RunOpt.Exploit = "auto"
	}

	if r.NoScan {
		Opt.Noscan = r.NoScan
	}

	// 加载配置文件中的全局变量
	templatesLoader()
	for _, e := range r.Extract {
		if reg, ok := ExtractRegexps[e]; ok {
			Extractors[e] = reg
		} else {
			Extractors[e] = []*regexp.Regexp{regexp.MustCompile(e)}
		}
	}

	if r.AttackType != "" {
		ExecuterOptions.Options.AttackType = r.AttackType
	}
	neutronLoader(r.ExploitFile, r.Payloads)
}

func (r *Runner) PrepareConfig() {
	r.Config = Config{
		GOGOConfig: &parsers.GOGOConfig{
			IP:        r.IP,
			Ports:     r.Ports,
			ListFile:  r.ListFile,
			JsonFile:  r.JsonFile,
			Threads:   r.Threads,
			PortSpray: r.PortSpray,
			Mod:       r.Mod,
		},
		IsListInput: r.IsListInput,
		IsJsonInput: r.IsJsonInput,
		PortProbe:   r.PortProbe,
		IpProbe:     r.IpProbe,
		NoSpray:     r.NoSpray,
		Filename:    r.Filename,
		FilePath:    r.FilePath,
		Compress:    !r.Compress,
		Tee:         r.Tee,
		Filters:     r.Filters,
		FilterOr:    r.FilterOr,
	}

	if r.FileOutputf == Default {
		r.Config.FileOutputf = "json"
	} else {
		r.Config.FileOutputf = r.FileOutputf
	}

	if r.Outputf == Default {
		r.Config.Outputf = "full"
	} else {
		r.Config.Outputf = r.Outputf
	}

	for _, filterStr := range r.OutputFilters {
		k, v, op := parseFilterString(filterStr)
		if op != "" {
			r.Config.OutputFilters = append(r.Config.OutputFilters, []string{k, v, op})
		}
	}

	if r.AutoFile {
		r.Config.Filenamef = "auto"
	} else if r.HiddenFile {
		r.Config.Filenamef = "hidden"
	}

	if r.Ping {
		r.Config.AliveSprayMod = append(r.Config.AliveSprayMod, "icmp")
	}

}

func (r *Runner) Run() {
	r.start = time.Now()
	if r.WorkFlowName == "" && !r.IsWorkFlow {
		r.runWithCMD()
	} else {
		var workflowMap = WorkflowMap{}
		if r.IsWorkFlow {
			workflowMap["tmp"] = ParseWorkflowsFromInput(LoadFile(os.Stdin))
			r.WorkFlowName = "tmp"
		} else if IsExist(r.WorkFlowName) {
			file, err := files.Open(r.WorkFlowName)
			if err != nil {
				iutils.Fatal(err.Error())
			}
			workflowMap["tmp"] = ParseWorkflowsFromInput(LoadFile(file))
			r.WorkFlowName = "tmp"
		} else {
			if bs, ok := parsers.DSLParser(r.WorkFlowName); ok {
				workflowMap["tmp"] = ParseWorkflowsFromInput(bs)
			} else {
				workflowMap = LoadWorkFlow()
			}
		}
		r.runWithWorkFlow(workflowMap)
	}
}

func (r *Runner) runWithCMD() {
	config := r.Config

	if config.Filename != "" {
		logs.Log.Warn("The result file has been specified, other files will not be created.")
	}

	if config.Filename == "" && config.IsBSmart() {
		config.SmartBFilename = GetFilename(&config, "bcidr")
	}
	if config.Filename == "" && config.IsSmart() {
		config.SmartCFilename = GetFilename(&config, "ccidr")
	}
	if config.Filename == "" && config.HasAlivedScan() {
		config.AlivedFilename = GetFilename(&config, "alived")
	}

	if config.Filenamef != "" {
		config.Filename = GetFilename(&config, config.FileOutputf)
	}

	preparedConfig, err := InitConfig(&config)
	if err != nil {
		iutils.Fatal(err.Error())
	}
	RunTask(*preparedConfig) // 运行
	r.Close(&config)
}

func (r *Runner) runWithWorkFlow(workflowMap WorkflowMap) {
	if workflows := workflowMap.Choice(r.WorkFlowName); len(workflows) > 0 {
		for _, workflow := range workflows {
			logs.Log.Important("workflow " + workflow.Name + " starting")
			config := workflow.PrepareConfig(r.Config)

			if config.Mod == SUPERSMARTB {
				config.FileOutputf = SUPERSMARTB
			}

			if config.Filename != "" {
				logs.Log.Warn("The result file has been specified, other files will not be created.")
			}

			if config.Filename == "" && config.IsBSmart() {
				config.SmartBFilename = GetFilename(config, "bcidr")
			}
			if config.Filename == "" && config.IsSmart() {
				config.SmartCFilename = GetFilename(config, "ccidr")
			}
			if config.Filename == "" && config.HasAlivedScan() {
				config.AlivedFilename = GetFilename(config, "alived")
			}
			if config.Filenamef != "" {
				config.Filename = GetFilename(config, config.FileOutputf)
			}

			// 全局变量的处理
			if !r.NoScan {
				Opt.Noscan = workflow.NoScan
			}

			if r.Verbose {
				RunOpt.VersionLevel = 1
			} else {
				RunOpt.VersionLevel = workflow.Verbose
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

			preparedConfig, err := InitConfig(config)
			if err != nil {
				iutils.Fatal(err.Error())
			}
			RunTask(*preparedConfig) // 运行
			r.Close(config)
			r.ResetGlobals()
		}
	} else {
		iutils.Fatal("not fount workflow " + r.WorkFlowName)
	}
}

func (r *Runner) Close(config *Config) {
	config.Close() // 关闭result与extract写入管道

	if r.HiddenFile {
		iutils.Chtime(config.Filename)
		if config.SmartBFile != nil && config.SmartBFile.InitSuccess {
			iutils.Chtime(config.SmartBFilename)
		}
		if config.SmartCFile != nil && config.SmartCFile.InitSuccess {
			iutils.Chtime(config.SmartBFilename)
		}
	}

	// 任务统计
	logs.Log.Importantf("Alived: %d, Total: %d", Opt.AliveSum, RunOpt.Sum)
	logs.Log.Important("Time consuming: " + time.Since(r.start).String())

	// 输出文件名
	if config.File != nil && config.File.InitSuccess {
		logs.Log.Importantf("Results: " + config.Filename)
	}
	if config.SmartBFile != nil && config.SmartBFile.InitSuccess {
		logs.Log.Important("B CIDRs result: " + config.SmartBFilename)
	}
	if config.SmartCFile != nil && config.SmartCFile.InitSuccess {
		logs.Log.Important("c CIDRs result: " + config.SmartCFilename)
	}
	if config.AliveFile != nil && config.AliveFile.Initialized {
		logs.Log.Important("Alived result: " + config.AlivedFilename)
	}
	if IsExist(config.Filename + "_extract") {
		logs.Log.Important("extractor result: " + config.Filename + "_extract")
	}
}

func (r *Runner) ResetGlobals() {
	Opt.Noscan = false
	RunOpt.Exploit = "none"
	RunOpt.VersionLevel = 0
	ResetFlag()
}

func printConfigs(t string) {
	if t == "port" {
		Printportconfig()
	} else if t == "nuclei" {
		PrintNeutronPoc()
	} else if t == "workflow" {
		PrintWorkflow()
	} else if t == "extract" {
		PrintExtract()
	} else {
		fmt.Println("choice port|nuclei|workflow|extract")
	}
}

func neutronLoader(pocfile string, payloads []string) {
	ExecuterOptions = ParserCmdPayload(payloads)
	TemplateMap = LoadNeutron(pocfile)
}

func templatesLoader() {
	LoadPortConfig()
	LoadExtractor()
	AllHttpFingers = LoadFinger("http")
	Mmh3Fingers, Md5Fingers = LoadHashFinger(AllHttpFingers)
	TcpFingers = LoadFinger("tcp").GroupByPort()
	HttpFingers = AllHttpFingers.GroupByPort()
}

func parseFilterString(s string) (k, v, op string) {
	if strings.Contains(s, "::") {
		kv := strings.Split(s, "::")
		return kv[0], kv[1], "::"
	} else if strings.Contains(s, "==") {
		kv := strings.Split(s, "==")
		return kv[0], kv[1], "=="
	} else if strings.Contains(s, "!=") {
		kv := strings.Split(s, "!=")
		return kv[0], kv[1], "!="
	} else if strings.Contains(s, "!:") {
		kv := strings.Split(s, "!:")
		return kv[0], kv[1], "!:"
	}
	return "", "", ""
}
