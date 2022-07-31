package pkg

import (
	"encoding/json"
	"fmt"
	"getitle/v1/pkg/utils"
	. "github.com/chainreactors/files"
	"github.com/chainreactors/ipcs"
	"github.com/chainreactors/logs"
	"strings"
)

type Config struct {
	// ip
	IP         string        `json:"ip"`
	IPlist     []string      `json:"ips"`
	CIDRs      ipcs.CIDRs    `json:"-"`
	ExcludeIPs string        `json:"-"`
	ExcludeMap map[uint]bool `json:"-"`

	// port and probe
	Ports         string   `json:"ports"` // 预设字符串
	Portlist      []string `json:"-"`     // 处理完的端口列表
	SmartPort     string   `json:"-"`     // 启发式扫描预设探针
	SmartPortList []string `json:"-"`     // 启发式扫描预设探针
	IpProbe       string   `json:"-"`
	IpProbeList   []uint   `json:"-"`

	// file
	JsonFile    string `json:"json_file"` // gt的结果json文件,可以再次读入扫描
	ListFile    string `json:"list_file"` // 目标ip列表
	IsListInput bool   `json:"-"`         // 从标准输入中读
	IsJsonInput bool   `json:"-"`         // 从标准输入中读

	// misc
	Threads       int      `json:"threads"` // 线程数
	Mod           string   `json:"mod"`     // 扫描模式
	AliveSprayMod []string `json:"alive_spray"`
	PortSpray     bool     `json:"port_spray"`
	NoSpray       bool     `json:"-"`
	Exploit       string   `json:"exploit"`
	JsonType      string   `json:"json_type"`
	VersionLevel  int      `json:"version_level"`
	Compress      bool     `json:"-"`

	// output
	//Output         string              `json:"-"`
	FilePath       string              `json:"-"`
	Filename       string              `json:"-"`
	SmartFilename  string              `json:"-"`
	AlivedFilename string              `json:"-"`
	File           *File               `json:"-"`
	SmartFile      *File               `json:"-"`
	ExtractFile    *File               `json:"-"`
	AliveFile      *File               `json:"-"`
	Outputf        string              `json:"-"`
	FileOutputf    string              `json:"-"`
	Filenamef      string              `json:"-"`
	Results        Results             `json:"-"` // json反序列化后的内网,保存在内存中
	HostsMap       map[string][]string `json:"-"` // host映射表
}

func (config *Config) InitIP() {
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
			cidr, err := ipcs.ParseCIDR(ip)
			if err != nil {
				logs.Log.Warn("Parse Ip Failed, " + err.Error())
			}
			config.CIDRs = append(config.CIDRs, cidr)
			if cidr.IP.Host != "" {
				config.HostsMap[cidr.IP.String()] = append(config.HostsMap[cidr.IP.String()], host)
			}
		}

		config.CIDRs = utils.Unique(config.CIDRs).(ipcs.CIDRs)
		if len(config.CIDRs) == 0 {
			utils.Fatal("all targets format error")
		}
	}
}

func (config *Config) InitFile() error {
	var err error
	// 初始化res文件handler
	if config.Filename != "" {
		logs.Log.Clean = !logs.Log.Clean
		// 创建output的filehandle
		config.File, err = newFile(config.Filename, config.Compress)
		if err != nil {
			utils.Fatal(err.Error())
		}
		if config.FileOutputf == "json" {
			var rescommaflag bool
			config.File.Write(fmt.Sprintf("{\"config\":%s,\"data\":[", config.ToJson("scan")))
			config.File.ClosedAppend = "]}"
			config.File.Handler = func(res string) string {
				if rescommaflag {
					// 只有json输出才需要手动添加逗号
					res = "," + res
				}
				if config.FileOutputf == "json" {
					// 如果json格式输出,则除了第一次输出,之后都会带上逗号
					rescommaflag = true
				}
				return res
			}
		}
		config.ExtractFile, err = newFile(config.Filename+"_extract", config.Compress)
	}

	// -af 参数下的启发式扫描结果handler初始化
	if config.SmartFilename != "" {
		config.SmartFile, err = newFile(config.SmartFilename, config.Compress)
		if err != nil {
			return err
		}

		config.SmartFile.Write(fmt.Sprintf("{\"config\":%s,\"data\":[", config.ToJson("smart")))
		config.SmartFile.ClosedAppend = "]}"
	}

	if config.AlivedFilename != "" {
		config.AliveFile, err = newFile(config.AlivedFilename, config.Compress)
		if err != nil {
			return err
		}
		config.AliveFile.Write(fmt.Sprintf("{\"config\":%s,\"data\":[", config.ToJson("ping")))
		config.AliveFile.ClosedAppend = "]}"
	}

	return nil
}

//func (config *Config) SyncFile() {
//	if config.File != nil {
//		config.File.SafeSync()
//	}
//}

func (config *Config) Close() {
	if config.File != nil {
		config.File.Close()
	}
	if config.SmartFile != nil {
		config.SmartFile.Close()
	}
	if config.AliveFile != nil {
		config.AliveFile.Close()
	}
	if config.ExtractFile != nil {
		config.ExtractFile.Close()
	}
}

func (config *Config) IsScan() bool {
	if config.IP != "" || config.ListFile != "" || config.JsonFile != "" || config.Mod == "a" {
		return true
	}
	return false
}

func (config *Config) IsSmart() bool {
	if utils.SliceContains([]string{"ss", "s", "sc"}, config.Mod) {
		return true
	}
	return false
}

func (config *Config) IsSmartScan() bool {
	if utils.SliceContains([]string{"ss", "s"}, config.Mod) {
		return true
	}
	return false
}

func (config *Config) IsASmart() bool {
	if utils.SliceContains([]string{"ss", "sc"}, config.Mod) {
		return true
	}
	return false
}

func (config *Config) IsBSmart() bool {
	if utils.SliceContains([]string{"s", "sb"}, config.Mod) {
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
		target = config.ListFile
	} else if config.JsonFile != "" {
		target = config.JsonFile
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
