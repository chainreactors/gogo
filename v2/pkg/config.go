package pkg

import (
	"encoding/json"
	"errors"
	"fmt"
	. "github.com/chainreactors/files"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/parsers"
	"github.com/chainreactors/parsers/iutils"
	"github.com/chainreactors/utils"
	"os"
	"os/signal"
	"path"
	"strings"
	"syscall"
)

const (
	SMART       = "s"       // 使用port-probe探测存活的c段, 递归下降到default
	SUPERSMART  = "ss"      // 使用ip-probe探测存活的b段, 递归下降到s
	SUPERSMARTC = "sb"      // 使用port-probe探测到c段后退出
	SUPERSMARTB = "sc"      // 使用ip-probe探测存活的b段,. 递归下降到sb
	Default     = "default" // 扫描完后退出
)

type Config struct {
	*parsers.GOGOConfig
	// ip
	CIDRs utils.CIDRs `json:"-"`

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
	File           *File               `json:"-"`
	SmartBFile     *File               `json:"-"`
	SmartCFile     *File               `json:"-"`
	AliveFile      *File               `json:"-"`
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

func (config *Config) Validate() error {
	if config.Filename != "" && IsExist(config.Filename) {
		return fmt.Errorf("file %s already exist!", config.Filename)
	}

	// 一些命令行参数错误处理,如果check没过直接退出程序或输出警告
	legalFormat := []string{"url", "ip", "port", "frameworks", "framework", "frame", "vuln", "vulns", "protocol", "scheme", "title", "target", "hash", "language", "host", "cert", "color", "c", "json", "j", "full", "jsonlines", "jl", "zombie", "sc", "csv", "status", "os"}
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
				logs.Log.Warnf("Parse IP %s Failed, skipped ", ip)
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
	return nil
}

func (config *Config) InitFile() error {
	var err error
	// 初始化res文件handler
	if config.Filename != "" {
		if config.Tee {
			logs.Log.Clean = false
		} else {
			logs.Log.Clean = true
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
				config.File.SafeSync()
				os.Exit(0)
			}()
		}()

		if config.FileOutputf == "jl" || config.FileOutputf == "jsonlines" {
			//var rescommaflag bool
			//config.File.Write(fmt.Sprintf("{\"config\":%s,\"data\":[", config.ToJson("scan")))
			config.File.WriteLine(config.ToJson("scan"))
			config.File.ClosedAppend = "[\"done\"]"
			//config.File.Handler = func(res string) string {
			//	if rescommaflag {
			//		// 只有json输出才需要手动添加逗号
			//		res = "," + res
			//	}
			//	if config.FileOutputf == "json" {
			//		// 如果json格式输出,则除了第一次输出,之后都会带上逗号
			//		rescommaflag = true
			//	}
			//	return res
			//}
		} else if config.FileOutputf == SUPERSMARTB {
			config.File.WriteLine(config.ToJson("smart"))
			config.File.ClosedAppend = "[\"done\"]"
			//config.File.Write(fmt.Sprintf("{\"config\":%s,\"data\":[", config.ToJson("smart")))
			//config.File.ClosedAppend = "]}"
		} else if config.FileOutputf == "csv" {
			config.File.Write("ip,port,url,status,title,host,language,midware,frame,vuln,extract\n")
		}
	}

	// -af 参数下的启发式扫描结果file初始化
	if config.SmartBFilename != "" {
		config.SmartBFile, err = newFile(config.SmartBFilename, config.Compress)
		if err != nil {
			return err
		}

		//config.SmartBFile.Write(fmt.Sprintf("{\"config\":%s,\"data\":[", config.ToJson("smartb")))
		//config.SmartBFile.ClosedAppend = "]}"
		config.SmartBFile.WriteLine(config.ToJson("smartb"))
		config.SmartBFile.ClosedAppend = "[\"done\"]"
	}

	if config.SmartCFilename != "" {
		config.SmartCFile, err = newFile(config.SmartCFilename, config.Compress)
		if err != nil {
			return err
		}

		//config.SmartCFile.Write(fmt.Sprintf("{\"config\":%s,\"data\":[", config.ToJson("smartc")))
		//config.SmartCFile.ClosedAppend = "]}"
		config.SmartCFile.WriteLine(config.ToJson("smartc"))
		config.SmartCFile.ClosedAppend = "[\"done\"]"
	}

	if config.AlivedFilename != "" {
		config.AliveFile, err = newFile(config.AlivedFilename, config.Compress)
		if err != nil {
			return err
		}
		//config.AliveFile.Write(fmt.Sprintf("{\"config\":%s,\"data\":[", config.ToJson("ping")))
		//config.AliveFile.ClosedAppend = "]}"
		config.AliveFile.WriteLine("alive")
		config.AliveFile.ClosedAppend = "[\"done\"]"
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
