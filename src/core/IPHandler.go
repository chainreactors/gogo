package core

import (
	"math"
	"net"
	"strconv"
	"strings"
)

func Ip2Int(ipmask string) uint {
	Ip := strings.Split(ipmask, "/")
	s2ip := net.ParseIP(Ip[0]).To4()
	return uint(s2ip[3]) | uint(s2ip[2])<<8 | uint(s2ip[1])<<16 | uint(s2ip[0])<<24
}

func Int2IP(ipint uint) string {
	ip := make(net.IP, net.IPv4len)
	ip[0] = byte(ipint >> 24)
	ip[1] = byte(ipint >> 16)
	ip[2] = byte(ipint >> 8)
	ip[3] = byte(ipint)
	return ip.String()
}

func GetMaskRange(mask string) (before uint, after uint) {
	IntMask, _ := strconv.Atoi(mask)

	before = uint(math.Pow(2, 32) - math.Pow(2, float64(32-IntMask)))
	after = uint(math.Pow(2, float64(32-IntMask)) - 1)
	return before, after
}

func GetIpRange(target string) (start uint, fin uint) {
	mask := strings.Split(target, "/")[1]

	before, after := GetMaskRange(mask)

	ipint := Ip2Int(target)

	start = ipint & before
	fin = ipint | after
	return start, fin
}

func TargetGenerator(ch chan string, portlist []string) chan string {
	targetChannel := make(chan string)

	go func() {
		for ip := range ch {
			for _, port := range portlist {
				targetChannel <- ip + ":" + port
			}
		}
		close(targetChannel)
	}()
	return targetChannel
}

//使用管道生成IP
func IpGenerator(target string) chan string {
	start, fin := GetIpRange(target)
	ch := make(chan string)
	var i uint
	go func() {
		for i = 0; i <= fin-start; i++ {
			// 如果是广播地址或网络地址,则跳过
			if (i+start)%256 != 255 && (i+start)%256 != 0 {
				ch <- Int2IP(i + start)
			}

		}
		close(ch)
	}()
	return ch
}

//此处的生成方式是每个C段交替生成,1.1,2.1....1.255,2.255这样
func SmartIpGenerator(target string, temp []int) chan string {
	start, fin := GetIpRange(target)
	ch := make(chan string)
	var outIP string
	//sum := fin -start
	var C, B uint

	go func() {
		for C = 1; C < 255; C++ {
			for B = 0; B <= (fin-start)/256; B++ {
				outIP = Int2IP(start + 256*B + C)
				if isAlive(outIP, temp) {
					ch <- outIP
				}
			}
		}
		close(ch)
	}()
	return ch
}

func isAlive(ip string, temp []int) bool {
	c := net.ParseIP(ip).To4()[2]
	if temp[c] > 0 {
		return false
	}
	return true
}

func BipGenerator(target string) chan string {
	start, fin := GetIpRange(target)
	startB := net.ParseIP(Int2IP(start)).To4()[1]
	finB := net.ParseIP(Int2IP(fin)).To4()[1]

	ch := make(chan string)

	ip := net.ParseIP(Int2IP(start)).To4()

	var i byte
	go func() {
		for i = startB; i <= finB; i++ {
			ip[1] = startB
			ch <- ip.String()
		}
		close(ch)
	}()
	return ch
}

func CheckIp(CIDR string) string {
	fmtip := GetIp(strings.Split(CIDR, "/")[0])
	if fmtip != "" {
		return fmtip + "/" + strings.Split(CIDR, "/")[1]
	}
	return ""
}

func isIPv4(ip string) bool {
	address := net.ParseIP(ip)
	if address != nil {
		return true
	}
	return false
}

func GetIp(target string) string {
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
