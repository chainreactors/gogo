package pkg

import (
	"encoding/json"
	"getitle/src/fingers"
	"getitle/src/utils"
	"regexp"
	"strings"
)

var (
	Md5Fingers  map[string]string
	Mmh3Fingers map[string]string
	AllFingers  fingers.Fingers
	TcpFingers  fingers.FingerMapper
	HttpFingers fingers.FingerMapper
	NameMap     PortMapper
	PortMap     PortMapper
	TagMap      PortMapper
	//WorkFlowMap    map[string][]*Workflow
	Compiled       map[string][]*regexp.Regexp
	CommonCompiled map[string]*regexp.Regexp
	Extractors     = make(map[string]*regexp.Regexp)
	Win            = utils.IsWin()
	Root           = utils.IsRoot()
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

type PortMapper map[string][]string
type PortFinger struct {
	Name  string   `json:"name"`
	Ports []string `json:"ports"`
	Type  []string `json:"type"`
}

func LoadPortConfig() (PortMapper, PortMapper, PortMapper) {
	var portfingers []PortFinger
	err := json.Unmarshal(LoadConfig("port"), &portfingers)

	if err != nil {
		Fatal("port config load FAIL!, " + err.Error())
	}
	tagmap := make(PortMapper)  // 以服务名归类
	namemap := make(PortMapper) // 以tag归类
	portmap := make(PortMapper) // 以端口号归类

	for _, v := range portfingers {
		v.Ports = parsePortsPreset(v.Ports)
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
func LoadFinger(t string) fingers.Fingers {
	fs, err := fingers.LoadFingers(LoadConfig(t))
	if err != nil {
		Fatal(err.Error())
	}
	for _, finger := range fs {
		err := finger.Compile(portSliceHandler)
		if err != nil {
			Fatal(err.Error())
		}
	}
	return fs
}

func LoadHashFinger() (map[string]string, map[string]string) {
	var mmh3fingers, md5fingers map[string]string
	var err error
	err = json.Unmarshal(LoadConfig("mmh3"), &mmh3fingers)
	if err != nil {
		Fatal("mmh3 load FAIL" + err.Error())
	}

	err = json.Unmarshal(LoadConfig("md5"), &md5fingers)
	if err != nil {
		Fatal("md5 load FAIL" + err.Error())
	}
	return mmh3fingers, md5fingers
}

func LoadWorkFlow() WorkflowMap {
	var workflows []*Workflow
	var err error
	err = json.Unmarshal(LoadConfig("workflow"), &workflows)
	if err != nil {
		Fatal("workflow load FAIL, " + err.Error())
	}

	// 设置默认参数
	for _, w := range workflows {
		// 参数默认值
		if w.IpProbe == "" {
			w.IpProbe = "default"
		}
		if w.SmartProbe == "" {
			w.SmartProbe = "default"
		}
		if w.Ports == "" {
			w.Ports = "top1"
		}
		if w.Mod == "" {
			w.Mod = "default"
		}
		if w.File == "" {
			w.File = "auto"
		}
		if w.Exploit == "" {
			w.Exploit = "none"
		}
	}

	var tmpmap = make(map[string][]*Workflow)
	for _, workflow := range workflows {
		tmpmap[strings.ToLower(workflow.Name)] = append(tmpmap[strings.ToLower(workflow.Name)], workflow)
		for _, tag := range workflow.Tags {
			tmpmap[strings.ToLower(tag)] = append(tmpmap[strings.ToLower(tag)], workflow)
		}
	}
	return tmpmap
}

type WorkflowMap map[string][]*Workflow

func (m WorkflowMap) Choice(name string) []*Workflow {
	var workflows []*Workflow
	name = strings.TrimSpace(name)
	names := strings.Split(name, ",")
	for _, n := range names {
		workflows = append(workflows, m[strings.ToLower(n)]...)
	}
	return workflows
}
