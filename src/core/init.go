package core

import (
	"encoding/json"
	"fmt"
	"getitle/src/Utils"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
)

var Datach = make(chan string, 100)
var FileHandle *os.File
var O2File = false
var Clean = false
var Filename string
var Threads int
var OutputType string
var Namemap, Typemap, Portmap map[string][]string = loadportconfig()

type PortFinger struct {
	Name  string   `json:"name"`
	Ports []string `json:"ports"`
	Type  []string `json:"type"`
}

func Init() {
	println("*********  getitle 0.3.0 beta by Sangfor  *********")
	initFile()
}

func RunTask(inp string, portlist []string, mod string, typ string) {
	var CIDR string
	if mod == "a" || inp == "auto" {
		// 内网探测默认使用icmp扫描
		CIDR = "auto"
		typ = "icmp"
	} else {
		CIDR = IpInit(inp)
		CIDR = checkIp(CIDR)
	}
	if CIDR == "" {
		println("[-] target (" + inp + ") format ERROR,")
		return
	}
	println(fmt.Sprintf("[*] Start Scan Task %s ,total ports: %d , mod: %s", CIDR, len(portlist), mod))
	if len(portlist) > 1000 {
		println("[*] too much ports , only show top 1000 ports: " + strings.Join(portlist[:1000], ",") + "......")
	} else {
		println("[*] ports: " + strings.Join(portlist, ","))
	}

	switch mod {
	case "default":
		//直接扫描
		StraightMod(CIDR, portlist)
	case "a", "auto":
		SmartBMod(CIDR, portlist, mod, typ)
	case "s", "f":
		//启发式扫描
		mask, _ := strconv.Atoi(strings.Split(CIDR, "/")[1])
		if mask < 24 && mask >= 16 {
			SmartBMod(CIDR, portlist, mod, typ)
		} else if mask < 16 {
			SmartAMod(CIDR, portlist, mod, typ)
		} else {
			StraightMod(CIDR, portlist)
		}
	default:
		StraightMod(CIDR, portlist)
	}
	FileHandle.Sync()
}

func ReadTargetFile(targetfile string) []string {

	file, err := os.Open(targetfile)
	if err != nil {
		println(err.Error())
		os.Exit(0)
	}
	defer file.Close()
	targetb, _ := ioutil.ReadAll(file)
	targets := strings.TrimSpace(string(targetb))
	return strings.Split(targets, "\n")
}

func TargetHandler(s string) (string, []string, string, string) {
	ss := strings.Split(s, " ")

	var mod, CIDR, typ string
	var portlist []string

	if len(ss) == 0 {
		return CIDR, portlist, mod, typ
	}

	CIDR = IpInit(ss[0])
	portlist = PortHandler("top1")
	mod = "default"
	typ = "socket"
	if len(ss) > 1 {
		portlist = PortHandler(ss[1])
	}
	if len(ss) > 2 {
		mod = ss[2]
	}
	if len(ss) > 3 {
		typ = ss[3]
	}
	return CIDR, portlist, mod, typ
}

func initFile() {
	var err error

	if Filename != "" {
		O2File = true
		if checkFileIsExist(Filename) { //如果文件存在
			FileHandle, err = os.OpenFile(Filename, os.O_APPEND|os.O_WRONLY, os.ModeAppend) //打开文件
			if err != nil {
				os.Exit(0)
			}
		} else {
			FileHandle, err = os.Create(Filename) //创建文件
			if err != nil {
				os.Exit(0)
			}
		}
		go write2File(FileHandle, Datach)

		if OutputType == "json" {
			_, _ = FileHandle.WriteString("[")
		}
	}
}

func checkFileIsExist(filename string) bool {
	var exist = true
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		exist = false
	}
	return exist
}

func write2File(FileHandle *os.File, Datach chan string) {
	for res := range Datach {
		FileHandle.WriteString(res)
	}
}

func PortHandler(portstring string) []string {
	var ports []string
	portstring = strings.Replace(portstring, "\r", "", -1)

	postslist := strings.Split(portstring, ",")
	for _, portname := range postslist {
		ports = append(ports, choiceports(portname)...)
	}
	ports = ports2PortSlice(ports)
	ports = removeDuplicateElement(ports)
	return ports

}

func loadportconfig() (map[string][]string, map[string][]string, map[string][]string) {
	var portfingers []PortFinger
	err := json.Unmarshal([]byte(Utils.LoadFingers("port")), &portfingers)

	if err != nil {
		println("[-] port config load FAIL!")
		os.Exit(0)
	}

	typemap := make(map[string][]string)
	namemap := make(map[string][]string)
	portmap := make(map[string][]string)

	for _, v := range portfingers {
		namemap[v.Name] = append(namemap[v.Name], v.Ports...)
		for _, t := range v.Type {
			typemap[t] = append(typemap[t], v.Ports...)
		}
		for _, p := range v.Ports {
			portmap[p] = append(portmap[p], v.Name)
		}
	}

	return typemap, namemap, portmap
}

// 端口预设
func choiceports(portname string) []string {
	var ports []string
	if portname == "all" {
		for p, _ := range Portmap {
			ports = append(ports, p)
		}
		return ports
	}

	if Namemap[portname] != nil {
		ports = append(ports, Namemap[portname]...)
		return ports
	} else if Typemap[portname] != nil {
		ports = append(ports, Typemap[portname]...)
		return ports
	} else {
		return []string{portname}
	}
}

func Listportconfig() {
	println("当前已有端口配置: (根据端口类型分类)")
	for k, v := range Namemap {
		println("	", k, ": ", strings.Join(v, ","))
	}
	println("当前已有端口配置: (根据服务分类)")
	for k, v := range Typemap {
		println("	", k, ": ", strings.Join(v, ","))
	}
}

func ports2PortSlice(ports []string) []string {
	var tmpports []string
	//生成端口列表 支持,和-
	for _, pr := range ports {
		if strings.Contains(pr, "-") {
			sf := strings.Split(pr, "-")
			start, _ := strconv.Atoi(sf[0])
			fin, _ := strconv.Atoi(sf[1])
			for port := start; port <= fin; port++ {
				tmpports = append(tmpports, strconv.Itoa(port))
			}
		} else {
			tmpports = append(tmpports, pr)
		}
	}
	return tmpports
}

//切片去重
func removeDuplicateElement(ss []string) []string {
	res := make([]string, 0, len(ss))
	temp := map[string]struct{}{}
	for _, item := range ss {
		if _, ok := temp[item]; !ok {
			temp[item] = struct{}{}
			res = append(res, item)
		}
	}
	return res
}
