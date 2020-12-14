package core

import (
	"math"
	"net"
	"strconv"
	"strings"
	"sync"
)

func ip2int(ipmask string) uint {
	Ip := strings.Split(ipmask, "/")
	s2ip := net.ParseIP(Ip[0]).To4()
	return uint(s2ip[3]) | uint(s2ip[2])<<8 | uint(s2ip[1])<<16 | uint(s2ip[0])<<24
}

func int2ip(ipint uint) string {
	ip := make(net.IP, net.IPv4len)
	ip[0] = byte(ipint >> 24)
	ip[1] = byte(ipint >> 16)
	ip[2] = byte(ipint >> 8)
	ip[3] = byte(ipint)
	return ip.String()
}

func getMaskRange(mask string) (before uint, after uint) {
	IntMask, _ := strconv.Atoi(mask)

	before = uint(math.Pow(2, 32) - math.Pow(2, float64(32-IntMask)))
	after = uint(math.Pow(2, float64(32-IntMask)) - 1)
	return before, after
}

func getIpRange(target string) (start uint, fin uint) {
	mask := strings.Split(target, "/")[1]

	before, after := getMaskRange(mask)

	ipint := ip2int(target)

	start = ipint & before
	fin = ipint | after
	return start, fin
}

func tcGenerator(ch chan string, portlist []string) chan TargetConfig {
	targetChannel := make(chan TargetConfig)
	var tc TargetConfig
	go func() {
		for ip := range ch {
			for _, port := range portlist {
				tc.ip = ip
				tc.port = port
				targetChannel <- tc
			}
		}
		close(targetChannel)
	}()
	return targetChannel
}

//使用管道生成IP
func defalutIpGenerator(CIDR string, ch chan string) chan string {
	start, fin := getIpRange(CIDR)
	for i := start; i <= fin; i++ {
		// 如果是广播地址或网络地址,则跳过
		if (i)%256 != 255 && (i)%256 != 0 {
			ch <- int2ip(i)
		}
	}

	return ch
}

//此处的生成方式是每个C段交替生成,1.1,2.1....1.255,2.255这样
func smartIpGenerator(CIDR string, ch chan string, temp *sync.Map) chan string {
	start, fin := getIpRange(CIDR)
	var outIP string
	//sum := fin -start
	var C, B uint

	for C = 1; C < 255; C++ {
		for B = 0; B <= (fin-start)/256; B++ {
			outIP = int2ip(start + 256*B + C)
			if isAlive(int2ip(start+256*B+1), temp) {
				ch <- outIP
			}
		}
	}

	return ch
}

func isAlive(ip string, temp *sync.Map) bool {
	_, ok := temp.Load(ip)
	return !ok
}

func bipGenerator(CIDR string) chan string {
	start, fin := getIpRange(CIDR)
	startB := net.ParseIP(int2ip(start)).To4()[1]
	finB := net.ParseIP(int2ip(fin)).To4()[1]

	ch := make(chan string)

	ip := net.ParseIP(int2ip(start)).To4()

	var i byte
	go func() {
		for i = startB; i <= finB; i++ {
			ip[1] = i
			ch <- ip.String()
		}
		close(ch)
	}()
	return ch
}

func firstInterGenerator(ch chan string) chan string {
	println("[*] Processing : 10.0.0.0/8")
	ch = firstIpGenerator("10.0.0.0/8", ch)
	println("[*] Processing : 172.16.0.0/12")
	ch = firstIpGenerator("172.16.0.0/12", ch)
	println("[*] Processing : 192.168.0.0/16")
	ch = firstIpGenerator("192.168.0.0/16", ch)
	return ch
}

func firstIpGenerator(CIDR string, ch chan string) chan string {
	start, end := getIpRange(CIDR)
	for i := start + 1; i < end; i += 256 {
		ch <- int2ip(i)
	}
	return ch
}

func ipGenerator(CIDR string, mod string, temp *sync.Map) chan string {
	ch := make(chan string)
	go func() {
		if mod == "a" {
			ch = firstInterGenerator(ch)
		} else if mod == "s" {
			ch = smartIpGenerator(CIDR, ch, temp)
		} else if mod == "f" {
			ch = firstIpGenerator(CIDR, ch)
		} else {
			ch = defalutIpGenerator(CIDR, ch)
		}
		close(ch)
	}()

	return ch
}

func checkIp(CIDR string) string {
	fmtip := getIp(strings.Split(CIDR, "/")[0])
	if fmtip != "" {
		return fmtip + "/" + strings.Split(CIDR, "/")[1]
	}
	println("[-] CIRD cannot find host:" + CIDR + "'s ip address")
	return ""
}

func isIPv4(ip string) bool {
	address := net.ParseIP(ip)
	if address != nil {
		return true
	}
	return false
}

func getIp(target string) string {
	if isIPv4(target) {
		return target
	}
	iprecords, _ := net.LookupIP(target)
	for _, ip := range iprecords {
		if isIPv4(ip.String()) {
			println("[*] parse domin SUCCESS, map " + target + " to " + ip.String())
			return ip.String()
		}
	}
	return ""
}

func IpInit(target string) string {
	target = strings.Replace(target, "http://", "", -1)
	target = strings.Replace(target, "https://", "", -1)
	if target[len(target)-1:] == "/" {
		target = target + "32"
	} else if !strings.Contains(target, "/") {
		target = target + "/32"
	}
	return target
}
