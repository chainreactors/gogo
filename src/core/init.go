package core

import (
	"fmt"
	"getitle/src/Utils"
	"io/ioutil"
	"os"
	"runtime"
	"strings"
)

var Datach = make(chan string, 100)
var FileHandle *os.File
var Output string
var Noscan bool
var FileOutput string
var Clean bool

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
	Spray    bool
}

func Init(config Config) Config {
	//println("*********  main 0.3.3 beta by Sangfor  *********")

	if config.Mod != "default" && config.List != "" {
		println("[-] error Smart scan config")
		os.Exit(0)
	}

	config.Portlist = PortHandler(config.Ports)
	if config.List != "" {
		config.IPlist = ReadTargetFile(config.List)
	}

	if config.Spray && config.Mod != "default" {
		println("[-] error Spray scan config")
		os.Exit(0)
	}

	//windows系统默认协程数为2000
	OS := runtime.GOOS
	if config.Threads == 4000 && OS == "windows" {
		config.Threads = 2000
	}

	if config.IP == "" && config.List == "" && config.Mod != "a" {
		os.Exit(0)
	}
	// 存在文件输出则停止命令行输出
	if config.Filename != "" {
		Clean = !Clean
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
		StraightMod(config)
	case "a", "auto":
		SmartBMod(config)
	case "s", "f":
		mask := getMask(config.IP)
		if mask >= 24 {
			StraightMod(config)
		} else {
			SmartBMod(config)
		}
	case "ss":
		mask := getMask(config.IP)
		if mask < 16 {
			SmartAMod(config)
		} else {
			SmartBMod(config)
		}
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
		if FileOutput == "json" && !Noscan {
			_, _ = FileHandle.WriteString("[")
		}

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

	if FileOutput == "json" && !Noscan {
		FileHandle.WriteString("]")
	}
	_ = FileHandle.Close()
}

func PortHandler(portstring string) []string {
	var ports []string
	portstring = strings.Replace(portstring, "\r", "", -1)

	postslist := strings.Split(portstring, ",")
	for _, portname := range postslist {
		ports = append(ports, choiceports(portname)...)
	}
	ports = Utils.Ports2PortSlice(ports)
	ports = Utils.SliceUnique(ports)
	return ports
}

// 端口预设
func choiceports(portname string) []string {
	var ports []string
	if portname == "all" {
		for p, _ := range Utils.Portmap {
			ports = append(ports, p)
		}
		return ports
	}

	if Utils.Namemap[portname] != nil {
		ports = append(ports, Utils.Namemap[portname]...)
		return ports
	} else if Utils.Typemap[portname] != nil {
		ports = append(ports, Utils.Typemap[portname]...)
		return ports
	} else {
		return []string{portname}
	}
}

func Listportconfig() {
	println("当前已有端口配置: (根据端口类型分类)")
	for k, v := range Utils.Namemap {
		println("	", k, ": ", strings.Join(v, ","))
	}
	println("当前已有端口配置: (根据服务分类)")
	for k, v := range Utils.Typemap {
		println("	", k, ": ", strings.Join(v, ","))
	}
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
