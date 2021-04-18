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
var Filename string
var Output string
var FileOutput string
var Clean bool
var Namemap, Typemap, Portmap map[string][]string = loadportconfig()

type PortFinger struct {
	Name  string   `json:"name"`
	Ports []string `json:"ports"`
	Type  []string `json:"type"`
}

type Config struct {
	IP       string
	IPlist   []string
	Ports    string
	Portlist []string
	List     string
	Threads  int
	Mod      string
	Typ      string
	Output   string
	Filename string
	Noscan   bool
}

func Init(config Config) Config {
	//println("*********  main 0.3.3 beta by Sangfor  *********")
	config.Portlist = PortHandler(config.Ports)
	if config.List != "" {
		config.IPlist = ReadTargetFile(config.List)
	}
	initFile(config.Filename)
	return config
}

func RunTask(config Config) {
	var taskname string = ""
	if config.Mod == "a" {
		// 内网探测默认使用icmp扫描
		taskname = "auto"
		config.Typ = "icmp"
	} else {
		config = IpInit(config)
		if config.IP != "" {
			taskname = config.IP
		} else if config.List != "" {
			taskname = config.List
		}
	}
	if taskname == "" {
		println("[-] No Task")
		os.Exit(0)
	}

	fmt.Println(fmt.Sprintf("[*] Start Scan Task %s ,total ports: %d , mod: %s", taskname, len(config.Portlist), config.Mod))
	if len(config.Portlist) > 1000 {
		fmt.Println("[*] too much ports , only show top 1000 ports: " + strings.Join(config.Portlist[:1000], ",") + "......")
	} else {
		fmt.Println("[*] ports: " + strings.Join(config.Portlist, ","))
	}
	switch config.Mod {
	case "default":
		//直接扫描
		StraightMod(config)
	case "a", "auto":
		SmartBMod(config)
	case "s", "f":
		//启发式扫描
		SmartBMod(config)

	default:
		StraightMod(config)
	}
}

func ReadTargetFile(targetfile string) []string {

	file, err := os.Open(targetfile)
	if err != nil {
		println(err.Error())
		os.Exit(0)
	}
	defer file.Close()
	targetb, _ := ioutil.ReadAll(file)
	targetstr := strings.TrimSpace(string(targetb))
	targetstr = strings.Replace(targetstr, "\r", "", -1)
	targets := strings.Split(targetstr, "\n")
	return targets
}

//func TargetHandler(s string) (string, []string, string, string) {
//	ss := strings.Split(s, " ")
//
//	var mod, CIDR, typ string
//	var portlist []string
//
//	if len(ss) == 0 {
//		return CIDR, portlist, mod, typ
//	}
//
//	CIDR = IpForamt(ss[0])
//	portlist = PortHandler("top1")
//	mod = "default"
//	typ = "socket"
//	if len(ss) > 1 {
//		portlist = PortHandler(ss[1])
//	}
//	if len(ss) > 2 {
//		mod = ss[2]
//	}
//	if len(ss) > 3 {
//		typ = ss[3]
//	}
//	return CIDR, portlist, mod, typ
//}

func initFile(filename string) {
	var err error

	if filename != "" {
		if checkFileIsExist(filename) { //如果文件存在
			//FileHandle, err = os.OpenFile(filename, os.O_APPEND|os.O_WRONLY, os.ModeAppend) //打开文件
			println("[-] File already exists")
			os.Exit(0)
		} else {
			FileHandle, err = os.Create(filename) //创建文件
			if err != nil {
				os.Exit(0)
			}
		}
		// json写入
		_, _ = FileHandle.WriteString("[")

		go write2File(FileHandle, Datach)

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

	FileHandle.WriteString("]")
	_ = FileHandle.Close()
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

func IpForamt(target string) string {
	target = strings.Replace(target, "http://", "", -1)
	target = strings.Replace(target, "https://", "", -1)
	target = strings.Trim(target, "/")
	if strings.Contains(target, "/") {
		ip := strings.Split(target, "/")[0]
		mask := strings.Split(target, "/")[1]
		if isIPv4(ip) {
			target = ip + "/" + mask
		} else {
			println("[-] error IPv4 " + ip)
			os.Exit(0)
		}
	}
	if !strings.Contains(target, "/") {
		if isIPv4(target) {
			target = target + "/32"
		} else {
			println("[-] error IPv4 " + target)
			os.Exit(0)
		}
	}
	return target
}

func IpInit(config Config) Config {
	if config.IP != "" {
		config.IP = IpForamt(config.IP)
	}
	if config.List != "" {
		for i, ip := range config.IPlist {
			config.IPlist[i] = IpForamt(ip)
		}
	}
	return config
}
