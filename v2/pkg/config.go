package pkg

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path"
	"strings"
	"syscall"

	"github.com/chainreactors/utils/fileutils"

	"github.com/chainreactors/logs"
	"github.com/chainreactors/parsers"
	"github.com/chainreactors/utils"
	"github.com/chainreactors/utils/iutils"
)

const (
	SMART       = "s"       // 使用port-probe探测存活的c段, 递归下降到default
	SUPERSMART  = "ss"      // 使用ip-probe探测存活的b段, 递归下降到s
	SUPERSMARTC = "sb"      // 使用port-probe探测到c段后退出
	SUPERSMARTB = "sc"      // 使用ip-probe探测存活的b段,. 递归下降到sb
	Default     = "default" // 扫描完后退出
)

// DefaultConfig 包含所有默认值的配置实例
// 基于 options.go 中的默认值和 runner.go 中的 PrepareConfig 方法
var DefaultConfig = Config{
	GOGOConfig: &parsers.GOGOConfig{
		Ports: "top1",  // 默认端口预设
		Mod:   Default, // "default" 扫描模式
	},
	RunnerOpt: DefaultRunnerOption, // 使用已定义的默认RunnerOption

	// 端口和探针相关
	PortProbe:   "default",      // 默认端口探针
	IpProbe:     "default",      // 默认IP探针
	IpProbeList: []uint{1, 254}, // 默认IP探针列表 [1, 254]

	Compress:    true,      // 默认启用压缩（注意：runner中是!r.Compress）
	Outputf:     "full",    // 默认完整输出格式
	FileOutputf: "default", // 默认文件输出格式

}

func NewDefaultConfig(opt *RunnerOption) Config {
	// 创建一个 DefaultConfig 的副本
	config := DefaultConfig
	config.RunnerOpt = opt
	return config
}

type Config struct {
	*parsers.GOGOConfig
	RunnerOpt *RunnerOption
	// ip
	CIDRs    utils.CIDRs `json:"-"`
	Excludes utils.CIDRs `json:"-"`
	// port and probe
	//Ports         string   `json:"ports"` // 预设字符串
	PortList      []string `json:"-"` // 处理完的端口列表
	PortProbe     string   `json:"-"` // 启发式扫描预设探针
	PortProbeList []string `json:"-"` // 启发式扫描预设探针
	IpProbe       string   `json:"-"`
	IpProbeList   []uint   `json:"-"`

	// file
	IsListInput bool `json:"-"` // 从标准输入中读
	IsJsonInput bool `json:"-"` // 从标准输入中读
	NoSpray     bool `json:"-"`
	Compress    bool `json:"-"`

	// output
	FilePath       string              `json:"-"`
	Filename       string              `json:"-"`
	SmartBFilename string              `json:"-"`
	SmartCFilename string              `json:"-"`
	AlivedFilename string              `json:"-"`
	File           *fileutils.File     `json:"-"`
	SmartBFile     *fileutils.File     `json:"-"`
	SmartCFile     *fileutils.File     `json:"-"`
	AliveFile      *fileutils.File     `json:"-"`
	Tee            bool                `json:"-"`
	Outputf        string              `json:"-"`
	FileOutputf    string              `json:"-"`
	Filenamef      string              `json:"-"`
	Results        parsers.GOGOResults `json:"-"` // json反序列化后的,保存在内存中
	HostsMap       map[string][]string `json:"-"` // host映射表
	Filters        []string            `json:"-"`
	FilterOr       bool                `json:"-"`
	OutputFilters  [][]string          `json:"-"`
}

func (config *Config) ToWorkflow() *Workflow {
	workflow := &Workflow{
		// 基本目标信息
		IP:     config.IP,
		IPlist: config.IPlist,

		// 扫描配置
		Ports:     config.Ports,
		Mod:       config.Mod,
		NoScan:    config.NoScan,
		IpProbe:   config.IpProbe,
		PortProbe: config.PortProbe,
		Exploit:   config.Exploit,
		Verbose:   config.VersionLevel,

		// 存活检测 - 如果AliveSprayMod包含icmp则启用Ping
		Ping: len(config.AliveSprayMod) > 0 && iutils.StringsContains(config.AliveSprayMod, "icmp"),

		// 输出配置
		File: config.Filename,
		Path: config.FilePath,

		// 生成基本信息
		Name:        config.GetTargetName(),
		Description: fmt.Sprintf("Generated workflow for target: %s", config.GetTarget()),
	}

	return workflow
}

func (config *Config) Validate() error {
	//if config.Filename != "" && files.IsExist(config.Filename) {
	//	return fmt.Errorf("file %s already exist!", config.Filename)
	//}

	// 一些命令行参数错误处理,如果check没过直接退出程序或输出警告
	legalFormat := []string{
		"url", "ip", "port", "frameworks", "framework", "frame", "vuln",
		"vulns", "protocol", "scheme", "title", "target", "hash",
		"language", "host", "cert", "color", "c", "json", "j", "full",
		"jsonlines", "jl", "zombie", "sc", "csv", "status", "os",
	}

	if config.FileOutputf != Default {
		for _, form := range strings.Split(config.FileOutputf, ",") {
			if !iutils.StringsContains(legalFormat, form) {
				logs.Log.Warnf("illegal file output format: %s, Please use one or more of the following formats: %s", form, strings.Join(legalFormat, ", "))
			}
		}
	}

	if config.Outputf != "full" {
		for _, form := range strings.Split(config.Outputf, ",") {
			if !iutils.StringsContains(legalFormat, form) {
				logs.Log.Warnf("illegal output format: %s, Please use one or more of the following formats: %s", form, strings.Join(legalFormat, ", "))
			}
		}
	}

	if config.JsonFile != "" {
		if config.Ports != "top1" {
			logs.Log.Warn("json input can not config ports")
		}
		if config.Mod != Default {
			logs.Log.Warn("input json can not config . Mod,default scanning")
		}
	}

	//if plugin.RunOpt.Delay <= 1 {
	//	logs.Log.Warn("delay less than 1s, it may cause the target to miss the scan")
	//}

	if config.IP == "" && config.ListFile == "" && config.JsonFile == "" && !config.IsJsonInput && !config.IsListInput { // 一些导致报错的参数组合
		return errors.New("no any target, please set -ip or -l or -j or stdin")
	}

	if config.JsonFile != "" && config.ListFile != "" {
		return errors.New("cannot set -j and -l flags at same time")
	}

	if !HasPingPriv() && (strings.Contains(config.Ports, "icmp") || strings.Contains(config.Ports, "ping") || iutils.StringsContains(config.AliveSprayMod, "icmp")) {
		logs.Log.Warn("current user is not root, icmp scan not work")
	}

	return nil
}

func (config *Config) InitIP() error {
	config.HostsMap = make(map[string][]string)
	// 优先处理ip
	if config.IP != "" {
		if strings.Contains(config.IP, ",") {
			config.IPlist = strings.Split(config.IP, ",")
		} else {
			config.IPlist = append(config.IPlist, config.IP)
		}
	}

	// 如果输入的是文件,则格式化所有输入值.如果无有效ip
	if config.IPlist != nil {
		for _, ip := range config.IPlist {
			var host string
			cidr := utils.ParseCIDR(ip)
			if cidr == nil {
				logs.Log.Warnf("Parse IP %s Failed, skipped ", strings.TrimSpace(ip))
				continue
			}
			config.CIDRs = append(config.CIDRs, cidr)
			if cidr.IP.Host != "" {
				config.HostsMap[cidr.IP.String()] = append(config.HostsMap[cidr.IP.String()], host)
			}
		}

		config.CIDRs = iutils.Unique(config.CIDRs).(utils.CIDRs)
		if len(config.CIDRs) == 0 {
			return fmt.Errorf("all targets format error, exit")
		}
	}

	//config.CIDRs = config.ExcludeCIDRs(config.CIDRs)
	return nil
}

func (config *Config) ExcludeCIDRs(cidrs utils.CIDRs) utils.CIDRs {
	if config.Excludes != nil {
		for _, ecidr := range config.Excludes {
			for i, c := range cidrs {
				if c.ContainsCIDR(ecidr) {
					cidrs = append(append(cidrs[:i], cidrs[i+1:]...), utils.DifferenceCIDR(c, ecidr)...)
				}
			}
		}
		return cidrs.Coalesce()
	} else {
		return cidrs
	}
}
func (config *Config) InitFile() error {
	var err error
	// 初始化res文件handler
	if config.Filename != "" {
		if config.Tee {
			logs.Log.SetClean(false)
		} else {
			logs.Log.SetClean(true)
		}

		// 创建output的filehandle
		config.File, err = newFile(config.Filename, config.Compress)
		if err != nil {
			iutils.Fatal(err.Error())
		}

		go func() {
			c := make(chan os.Signal, 2)
			signal.Notify(c, os.Interrupt, syscall.SIGTERM)
			go func() {
				<-c
				logs.Log.Debug("save and exit!")
				config.File.Sync()
				os.Exit(0)
			}()
		}()

		if config.FileOutputf == "jl" || config.FileOutputf == "jsonlines" {
			config.File.WriteLine(config.ToJson("scan"))
			config.File.ClosedAppend = "[\"done\"]\n"
		} else if config.FileOutputf == SUPERSMARTB {
			config.File.WriteLine(config.ToJson("smart"))
			config.File.ClosedAppend = "[\"done\"]\n"
		} else if config.FileOutputf == "csv" {
			config.File.WriteString("ip,port,url,status,title,host,language,midware,frame,vuln,extract\n")
		}
	}

	// -af 参数下的启发式扫描结果file初始化
	if config.SmartBFilename != "" {
		config.SmartBFile, err = newFile(config.SmartBFilename, config.Compress)
		if err != nil {
			return err
		}
		config.SmartBFile.WriteLine(config.ToJson("smartb"))
		config.SmartBFile.ClosedAppend = "[\"done\"]\n"
	}

	if config.SmartCFilename != "" {
		config.SmartCFile, err = newFile(config.SmartCFilename, config.Compress)
		if err != nil {
			return err
		}
		config.SmartCFile.WriteLine(config.ToJson("smartc"))
		config.SmartCFile.ClosedAppend = "[\"done\"]\n"
	}

	if config.AlivedFilename != "" {
		config.AliveFile, err = newFile(config.AlivedFilename, config.Compress)
		if err != nil {
			return err
		}
		config.AliveFile.WriteLine(config.ToJson("alive"))
		config.AliveFile.ClosedAppend = "[\"done\"]\n"
	}

	return nil
}

func (config *Config) Close() {
	if config.File != nil {
		config.File.Close()
	}
	if config.SmartBFile != nil {
		config.SmartBFile.Close()
	}
	if config.SmartCFile != nil {
		config.SmartCFile.Close()
	}
	if config.AliveFile != nil {
		config.AliveFile.Close()
	}
}

func (config *Config) IsScan() bool {
	if config.IP != "" || config.ListFile != "" || config.JsonFile != "" {
		return true
	}
	return false
}

func (config *Config) IsSmart() bool {
	if iutils.StringsContains([]string{SUPERSMART, SMART, SUPERSMARTB}, config.Mod) {
		return true
	}
	return false
}

func (config *Config) IsBSmart() bool {
	if iutils.StringsContains([]string{SUPERSMART, SUPERSMARTB}, config.Mod) {
		return true
	}
	return false
}

func (config *Config) IsCSmart() bool {
	if iutils.StringsContains([]string{SMART, SUPERSMARTC}, config.Mod) {
		return true
	}
	return false
}

func (config *Config) HasAlivedScan() bool {
	if len(config.AliveSprayMod) > 0 {
		return true
	}
	return false
}

func (config *Config) GetTarget() string {
	if config.IP != "" {
		return config.IP
	} else if config.ListFile != "" {
		return strings.Join(config.IPlist, ",")
	} else if config.JsonFile != "" {
		return config.JsonFile
	} else {
		return ""
	}
}

func (config *Config) GetTargetName() string {
	var target string
	if config.ListFile != "" {
		target = path.Base(config.ListFile)
	} else if config.JsonFile != "" {
		target = path.Base(config.JsonFile)
	} else if config.Mod == "a" {
		target = "auto"
	} else if config.IP != "" {
		target = config.IP
	}
	return target
}

func (config *Config) ToJson(json_type string) string {
	config.JsonType = json_type
	s, err := json.Marshal(config)
	if err != nil {
		return err.Error()
	}
	return string(s)
}

var DefaultRunnerOption = &RunnerOption{
	Exploit:      "none",
	VersionLevel: 0,
	Delay:        2,
	HttpsDelay:   2,
	ScanFilters:  nil,
	Debug:        false,
	Opsec:        false,
	ExcludeCIDRs: nil,
}

type RunnerOption struct {
	Exploit      string
	VersionLevel int
	Delay        int
	HttpsDelay   int
	ScanFilters  [][]string
	//SuffixStr    string
	Debug        bool
	Opsec        bool // enable opsec
	ExcludeCIDRs utils.CIDRs
}
