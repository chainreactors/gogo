package utils

import (
	"encoding/json"
	"fmt"
	"getitle/src/structutils"
	"os"
	"regexp"
	"strconv"
	"strings"
)

var (
	Md5Fingers  map[string]string
	Mmh3Fingers map[string]string
	AllFingers  []*Finger
	TcpFingers  FingerMapper
	HttpFingers FingerMapper
	NameMap     PortMapper
	PortMap     PortMapper
	TagMap      PortMapper
	//WorkFlowMap    map[string][]*WorkFlow
	Compiled       map[string][]*regexp.Regexp
	CommonCompiled map[string]*regexp.Regexp
	Extractors     = make(map[string]*regexp.Regexp)
	Win            = structutils.IsWin()
	Root           = structutils.IsRoot()
)

var PresetExtracts = map[string]*regexp.Regexp{
	"url":      regexp.MustCompile("^(http(s)?:\\/\\/)[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+(:[0-9]{1,5})?[-a-zA-Z0-9()@:%_\\\\\\+\\.~#?&//=]*$"),
	"ip":       regexp.MustCompile("((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})(\\.((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})){3}"),
	"mail":     regexp.MustCompile("^([A-Za-z0-9_\\-\\.\u4e00-\u9fa5])+\\@([A-Za-z0-9_\\-\\.])+\\.([A-Za-z]{2,8})$"),
	"idcard":   regexp.MustCompile("^(\\d{15}$)|(^\\d{17}([0-9]|[xX]))$"),
	"phone":    regexp.MustCompile("^(\\+?0?86\\-?)?1[3-9]\\d{9}$"),
	"header":   regexp.MustCompile("(?U)^HTTP(?:.|\n)*[\r\n]{4}"),
	"body":     regexp.MustCompile("[\\r\\n]{4}[\\w\\W]*"),
	"cookie":   regexp.MustCompile("(?i)Set-Cookie.*"),
	"response": regexp.MustCompile("(?s).*"),
}

func Ports2PortSlice(ports []string) []string {
	var tmpports []string
	//生成端口列表 支持,和-
	for _, pr := range ports {
		if len(pr) == 0 {
			continue
		}
		pr = strings.TrimSpace(pr)
		if pr[0] == 45 {
			pr = "1" + pr
		}
		if pr[len(pr)-1] == 45 {
			pr = pr + "65535"
		}
		tmpports = append(tmpports, port2PortSlice(pr)...)
	}
	return tmpports
}

func port2PortSlice(port string) []string {
	var tmpports []string
	if strings.Contains(port, "-") {
		sf := strings.Split(port, "-")
		start, _ := strconv.Atoi(sf[0])
		fin, _ := strconv.Atoi(sf[1])
		for port := start; port <= fin; port++ {
			tmpports = append(tmpports, strconv.Itoa(port))
		}
	} else {
		tmpports = append(tmpports, port)
	}
	return tmpports
}

func LoadPortConfig() (PortMapper, PortMapper, PortMapper) {
	var portfingers []PortFinger
	err := json.Unmarshal(LoadConfig("port"), &portfingers)

	if err != nil {
		fmt.Println("[-] port config load FAIL!")
		os.Exit(0)
	}
	tagmap := make(PortMapper)  // 以服务名归类
	namemap := make(PortMapper) // 以tag归类
	portmap := make(PortMapper) // 以端口号归类

	for _, v := range portfingers {
		v.Ports = Ports2PortSlice(v.Ports)
		namemap[v.Name] = append(namemap[v.Name], v.Ports...)
		for _, t := range v.Type {
			tagmap[t] = append(tagmap[t], v.Ports...)
		}
		for _, p := range v.Ports {
			portmap[p] = append(portmap[p], v.Name)
		}
	}

	return tagmap, namemap, portmap
}

//加载指纹到全局变量
func LoadFingers(t string) FingerMapper {
	var tmpfingers []*Finger
	var fingermap = make(FingerMapper)
	// 根据权重排序在python脚本中已经实现

	err := json.Unmarshal(LoadConfig(t), &tmpfingers)
	if err != nil {
		fmt.Println("[-] finger load FAIL!")
		os.Exit(0)
	}
	if t == "http" {
		AllFingers = tmpfingers
	}
	for _, finger := range tmpfingers {
		finger.Protocol = t
		finger.Decode() // 防止\xff \x00编码解码影响结果

		// 普通指纹, 预编译
		for _, regstr := range finger.Regexps.Regexp {
			Compiled[finger.Name] = append(Compiled[finger.Name], CompileRegexp("(?im)"+regstr))
		}
		// 漏洞指纹预编译,指纹名称后接 "_vuln"
		for _, regstr := range finger.Regexps.Vuln {
			Compiled[finger.Name+"_vuln"] = append(Compiled[finger.Name+"_vuln"], CompileRegexp("(?im)"+regstr))
		}

		// http默认为80
		if finger.Defaultport == nil && finger.Protocol == "http" {
			finger.Defaultport = []string{"80"}
		}

		// 根据端口分类指纹
		for _, ports := range finger.Defaultport {
			for _, port := range port2PortSlice(ports) {
				fingermap[port] = append(fingermap[port], finger)
			}
		}

	}
	return fingermap
}

func LoadHashFinger() (map[string]string, map[string]string) {
	var mmh3fingers, md5fingers map[string]string
	var err error
	err = json.Unmarshal(LoadConfig("mmh3"), &mmh3fingers)
	if err != nil {
		Panic("mmh3 load FAIL" + err.Error())
	}

	err = json.Unmarshal(LoadConfig("md5"), &md5fingers)
	if err != nil {
		Panic("md5 load FAIL" + err.Error())
	}
	return mmh3fingers, md5fingers
}

func LoadWorkFlow() WorkflowMap {
	var workflows []*WorkFlow
	var err error
	err = json.Unmarshal(LoadConfig("workflow"), &workflows)
	if err != nil {
		Panic("workflow load FAIL, " + err.Error())
	}
	var tmpmap = make(map[string][]*WorkFlow)
	for _, workflow := range workflows {
		tmpmap[strings.ToLower(workflow.Name)] = append(tmpmap[strings.ToLower(workflow.Name)], workflow)
		for _, tag := range workflow.Tags {
			tmpmap[strings.ToLower(tag)] = append(tmpmap[strings.ToLower(tag)], workflow)
		}
	}
	return tmpmap
}

type WorkflowMap map[string][]*WorkFlow

func (m WorkflowMap) Choice(name string) []*WorkFlow {
	var workflows []*WorkFlow
	name = strings.TrimSpace(name)
	names := strings.Split(name, ",")
	for _, n := range names {
		workflows = append(workflows, m[n]...)
	}
	return workflows
}
