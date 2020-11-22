package core

import (
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
)

var Datach = make(chan string, 1000)
var FileHandle *os.File
var O2File bool = false
var IsJson bool = false
var Filename string
var Threads int
var OutputType string

func Init() {
	println("*********  getitle 0.2.0 beta by Sangfor  *********")

	//if key != "sangfor" {
	//	println("FUCK OFF!!!")
	//	os.Exit(0)
	//}
	initFile()
	go Write2File(FileHandle, Datach)
}

func IpInit(ip string) string {
	if !strings.Contains(ip, "/") {
		ip += "/32"
	}
	return ip
}

func RunTask(CIDR string, portlist []string, mod string) {
	CIDR = cuthttpstr(CIDR)
	CIDR = CheckIp(CIDR)
	if CIDR == "" {
		println("[-] target (" + CIDR + ") format ERROR,")
		return
	}
	println(fmt.Sprintf("[*] Start Scan Task %s ,total ports: %d , mod: %s", CIDR, len(portlist), mod))
	switch mod {
	case "default":
		//直接扫描
		StraightMod(CIDR, portlist, Threads)
	case "s", "smart":
		//启发式扫描
		mask, _ := strconv.Atoi(strings.Split(CIDR, "/")[1])
		if mask < 24 && mask >= 16 {
			SmartBMod(CIDR, portlist)
		} else if mask < 16 {
			SmartAMod(CIDR, portlist)
		} else {
			StraightMod(CIDR, portlist, Threads)
		}
	default:
		StraightMod(CIDR, portlist, Threads)
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

func TargetHandler(s string) (string, []string, string) {
	ss := strings.Split(s, " ")
	var mod, CIDR string
	var portlist []string
	if len(ss) == 3 {
		CIDR = ss[0]
		portlist = PortHandler(ss[1])
		mod = ss[2]
	} else {
		CIDR = ss[0]
		portlist = PortHandler(ss[1])
		mod = "default"
	}
	return CIDR, portlist, mod
}

func initFile() {
	var err error

	if Filename != "" {
		O2File = true
		if CheckFileIsExist(Filename) { //如果文件存在
			FileHandle, err = os.OpenFile(Filename, os.O_APPEND|os.O_WRONLY, os.ModeAppend) //打开文件
			//fmt.Println("文件存在")
			if err != nil {
				os.Exit(0)
			}
			//io.WriteString(FileHandle, "123")
		} else {
			FileHandle, err = os.Create(Filename) //创建文件
			//fmt.Println("文件不存在")
			if err != nil {
				os.Exit(0)
			}
			//io.WriteString(FileHandle, "123")
		}
		if OutputType == "json" {
			_, _ = FileHandle.WriteString("[")
		}
	}
}

func CheckFileIsExist(filename string) bool {
	var exist = true
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		exist = false
	}
	return exist
}

func Write2File(FileHandle *os.File, Datach chan string) {
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
	ports = Ports2PortSlice(ports)
	ports = removeDuplicateElement(ports)
	return ports

}

// 端口预设
func choiceports(portname string) []string {
	var ports []string
	switch portname {
	case "top1":
		ports = []string{"80", "443", "8080"}
	case "top2":
		ports = []string{"80-90", "443", "1080", "3000", "4443", "7000-7009", "9000-9009", "8080-8090", "8000-8020", "8443", "8787", "7080", "8070", "7070", "9080", "5555", "6666", "7777", " 9999", "8888", "8889", "9090", "8091", "8099", "8848", "8060", "8899", "800", "801", "10000", "10080", "10800"}
	case "top3":

		// 一些待定端口,需要更多测试
		//"8444-8447" "10800-10810" '10080"
		ports = []string{"4430", "9443", "6080", "6443", "9091", "8100-8110", "8021-8030", "8880-8890", "8010-8020", "8090-8100", "8180-8181", "8800", "8761", "8873", "8866", "8900", "8282", "8999", "8989", "8066", "8200", "8111", "8030", "8040", "8060", "8180"}
	case "db":
		ports = []string{"3306", "3307", "1433", "1521", "5432", "6379", "11211", "27017"}
	case "rce":
		ports = []string{"1090", "1098", "1099", "4444", "11099", "47001", "47002", "10999", "45000", "45001", "8686", "9012", "50500", "4848", "6443", "11111", "4445", "4786", "5555", "5556"}
	case "win":
		ports = []string{"21", "22", "23", "53", "88", "135", "137", "139", "389", "445", "1080", "3389", "5985"}
	case "all":
		ports = []string{"25", "69", "110", "143", "161", "389", "465", "873", "993", "995", "1158", "1352", "1833", "1863", "2049", "2100", "2181", "2375", "3128", "3700", "5632", "5900", "5984", "6000", "6868", "8069", "8161", "9081", "9200", "9300", "9043", "12345", "50000", "50070"}
		ports = append(ports, choiceports("top2")...)
		ports = append(ports, choiceports("top3")...)
		ports = append(ports, choiceports("db")...)
		ports = append(ports, choiceports("win")...)
		ports = append(ports, choiceports("rce")...)
	default:
		ports = []string{portname}
	}
	return ports
}

func Ports2PortSlice(ports []string) []string {
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
	result := make([]string, 0, len(ss))
	temp := map[string]struct{}{}
	for _, item := range ss {
		if _, ok := temp[item]; !ok {
			temp[item] = struct{}{}
			result = append(result, item)
		}
	}
	return result
}

func cuthttpstr(target string) string {
	target = strings.Replace(target, "http://", "", -1)
	target = strings.Replace(target, "https://", "", -1)
	return target
}
