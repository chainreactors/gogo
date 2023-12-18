package core

import (
	"fmt"
	"github.com/chainreactors/neutron/templates_gogo"
	"github.com/chainreactors/utils/encode"
	"golang.org/x/net/proxy"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/chainreactors/files"
	. "github.com/chainreactors/gogo/v2/internal/plugin"
	. "github.com/chainreactors/gogo/v2/pkg"
	"github.com/chainreactors/gogo/v2/pkg/fingers"
	"github.com/chainreactors/logs"
	neuhttp "github.com/chainreactors/neutron/protocols/http"
	"github.com/chainreactors/parsers"
	"github.com/chainreactors/utils/iutils"
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
		logs.Log = logs.NewLogger(0)
		logs.Log.SetQuiet(true)
	} else {
		if r.Debug {
			logs.Log.SetLevel(logs.Debug)
		}
		logs.Log.SetFile(".sock.lock")
		logs.Log.Init()
	}

	RunOpt = RunnerOpts{
		Delay:        r.Delay,
		HttpsDelay:   r.HttpsDelay,
		VersionLevel: setVersionLevel(r.Verbose),
		Exploit:      setExploit(r.ExploitName, r.Exploit),
		Debug:        r.Debug,
		Opsec:        r.Opsec,
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

	var err error
	if r.Exclude != "" {
		r.Config.Excludes = strings.Split(r.Exclude, ",")
	} else if r.ExcludeList != "" {
		r.Config.Excludes, err = files.LoadFileToSlice(r.ExcludeList)
		if err != nil {
			logs.Log.Error(err.Error())
			return false
		}
	}

	if r.FormatterFilename != "" {
		var formatOut string
		if r.Outputf == Default {
			formatOut = "color"
		} else {
			formatOut = r.Outputf
		}
		FormatOutput(r.FormatterFilename, r.Config.Filename, formatOut, r.Config.Filenamef, r.Filters, r.FilterOr)
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
	// 加载配置文件中的全局变量
	templatesLoader()
	for _, e := range r.Extract {
		if reg, ok := ExtractRegexps[e]; ok {
			Extractors[e] = reg
		} else {
			Extractors[e] = []*parsers.Extractor{
				&parsers.Extractor{
					Name:            e,
					CompiledRegexps: []*regexp.Regexp{regexp.MustCompile(e)},
				},
			}
		}
	}

	if r.AttackType != "" {
		ExecuterOptions.Options.AttackType = r.AttackType
	}
	neutronLoader(r.ExploitFile, r.Payloads)

	if r.Opsec {
		templates.OPSEC = true
		fingers.OPSEC = true
		RunOpt.Opsec = true
	}
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
		r.Config.FileOutputf = "jl"
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
			if bs, ok := encode.DSLParser(r.WorkFlowName); ok {
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
				Opt.NoScan = workflow.NoScan
			}

			if r.Verbose != nil {
				RunOpt.VersionLevel = setVersionLevel(r.Verbose)
			} else {
				RunOpt.VersionLevel = workflow.Verbose
			}

			if RunOpt.Exploit != "none" {
				RunOpt.Exploit = setExploit(r.ExploitName, r.Exploit)
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
	Opt.NoScan = false
	RunOpt.Exploit = "none"
	RunOpt.VersionLevel = 0
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
	fingers.Mmh3Fingers, fingers.Md5Fingers, ActiveFavicons = LoadHashFinger(AllHttpFingers)
	SocketFingers = LoadFinger("tcp").GroupByPort()
	ActiveHttpFingers, PassiveHttpFingers = AllHttpFingers.GroupByMod()
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

func setVersionLevel(v []bool) int {
	if len(v) == 1 {
		return 1
	} else if len(v) == 2 {
		return 2
	}
	return 0
}

func setExploit(name string, enable bool) string {
	if name != "" {
		return name
	} else if enable {
		return "auto"
	}
	return "none"
}
