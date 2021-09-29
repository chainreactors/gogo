package utils

import (
	b64 "encoding/base64"
)

// common struct
func decode(s string) []byte {
	var bs []byte
	if s[:4] == "b64|" {
		bs, _ = b64.StdEncoding.DecodeString(s[4:])
	} else {
		bs = []byte(s)
	}
	return bs
}

type Finger struct {
	Name         string   `json:"name"`
	Protocol     string   `json:"protocol"`
	SendData_str string   `json:"send_data"`
	SendData     senddata `json:"-"`
	Vuln         string   `json:"vuln"`
	Level        int      `json:"level"`
	Defaultport  []string `json:"default_port"`
	Regexps      Regexps  `json:"regexps"`
}

func (f *Finger) Decode() {
	if f.Protocol != "tcp" {
		return
	}

	if f.SendData_str != "" {
		f.SendData = decode(f.SendData_str)
	}
	// todo
	// regexp decode
}

type senddata []byte

func (d senddata) IsNull() bool {
	if len(d) == 0 {
		return true
	}
	return false
}

type Regexps struct {
	HTML   []string `json:"html"`
	MD5    []string `json:"md5"`
	Regexp []string `json:"regexp"`
	Cookie []string `json:"cookie"`
	Header []string `json:"header"`
	Vuln   []string `json:"vuln"`
}

type PortFinger struct {
	Name  string   `json:"name"`
	Ports []string `json:"ports"`
	Type  []string `json:"type"`
}

type PortMapper map[string][]string

type FingerMapper map[string][]Finger

func (fm FingerMapper) GetFingers(k string) []Finger {
	return fm[k]
}

type ResultsData struct {
	Config Config   `json:"config"`
	Data   []Result `json:"data"`
	IP     string   `json:"ip"`
}

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
	Spray         bool     `json:"-"`
	NoSpray       bool     `json:"-"`
}

func (config Config) IsScan() bool {
	if config.IP != "" || config.ListFile != "" || config.JsonFile != "" || config.Mod == "a" {
		return true
	}
	return false
}
