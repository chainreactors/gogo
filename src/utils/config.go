package utils

import "getitle/src/structutils"

type Config struct {
	IP            string   `json:"ip"`
	IPlist        []string `json:"ips"`
	Ports         string   `json:"ports"`   // 预设字符串
	Portlist      []string `json:"-"`       // 处理完的端口列表
	JsonFile      string   `json:"-"`       // gt的结果json文件,可以再次读入扫描
	Results       []Result `json:"-"`       // json反序列化后的内网,保存在内存中
	ListFile      string   `json:"-"`       // 目标ip列表
	Threads       int      `json:"threads"` // 线程数
	Mod           string   `json:"mod"`     // 扫描模式
	SmartPort     string   `json:"-"`       // 启发式扫描预设探针
	SmartPortList []string `json:"-"`       // 启发式扫描预设探针
	IpProbe       string   `json:"-"`
	IpProbeList   []uint   `json:"-"`
	Output        string   `json:"-"`
	Filename      string   `json:"-"`
	SmartFilename string   `json:"-"`
	Spray         bool     `json:"-"`
	NoSpray       bool     `json:"-"`
	Exploit       string   `json:"exploit"`
	VerisonLevel  int      `json:"version_level"`
}

func (config Config) IsScan() bool {
	if config.IP != "" || config.ListFile != "" || config.JsonFile != "" || config.Mod == "a" {
		return true
	}
	return false
}

func (config Config) IsSmart() bool {
	if structutils.SliceContains([]string{"ss", "s", "sc"}, config.Mod) {
		return true
	}
	return false
}

func (config Config) IsSSmart2() bool {
	if structutils.SliceContains([]string{"ss", "sc"}, config.Mod) {
		return true
	}
	return false
}

func (config Config) IsSmart1() bool {
	if structutils.SliceContains([]string{"s", "sb"}, config.Mod) {
		return true
	}
	return false
}
