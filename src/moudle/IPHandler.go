package moudle

import (
	"math"
	"net"
	"strconv"
	"strings"
)

func Ip2Int(ipmask string) int {
	ParseIP := strings.Split(ipmask, "/")
	s2ip := net.ParseIP(ParseIP[0]).To4()
	return int(s2ip[3]) | int(s2ip[2])<<8 | int(s2ip[1])<<16 | int(s2ip[0])<<24
}

func Int2IP(ipint int) string {
	ip := make(net.IP, net.IPv4len)
	ip[0] = byte(ipint >> 24)
	ip[1] = byte(ipint >> 16)
	ip[2] = byte(ipint >> 8)
	ip[3] = byte(ipint)
	return ip.String()
}

func GetMaskRange(mask string) (before int, after int) {
	IntMask, _ := strconv.Atoi(mask)

	before = int(math.Pow(2, 32) - math.Pow(2, float64(32-IntMask)))
	after = int(math.Pow(2, float64(32-IntMask)) - 1)
	return before, after
}

func GetIpRange(target string) (start int, fin int) {
	mask := strings.Split(target, "/")[1]

	before, after := GetMaskRange(mask)

	ipint := Ip2Int(target)

	start = ipint & before
	fin = ipint | after
	return start, fin
}

func TargetGenerator(ch chan string, portlist []string) chan string {
	Tchan := make(chan string)

	go func() {
		for ip := range ch {
			for _, port := range portlist {
				Tchan <- ip + ":" + port
			}
		}
		close(Tchan)
	}()
	return Tchan
}

//使用管道生成IP
func Ipgenerator(target string) chan string {
	start, fin := GetIpRange(target)
	ch := make(chan string)
	sum := fin - start
	var i int
	go func() {
		for i = 0; i <= sum; i++ {
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
	start, _ := GetIpRange(target)
	ch := make(chan string)
	var outIP string
	//sum := fin -start
	var i, j int

	go func() {
		for i = 1; i < 255; i++ {
			for j = 0; j < 256; j++ {
				outIP = Int2IP(start + 256*j + i)
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

//func GenIPC(alive []string, AliveNum int) chan string {
//	Tchan := make(chan string)
//	var target string
//	for _, v := range alive {
//		go func() {
//			for i := 0; i <= 256*AliveNum; i++ {
//				target = <-Ipgenerator(v)
//				Tchan <- target
//			}
//			close(Tchan)
//
//		}()
//		return Tchan
//	}
//	return Tchan
//}

//
func GenBIP(target string) chan string {
	start, fin := GetIpRange(target)
	startB := byte(start >> 16)
	finB := byte((fin + 1) >> 16)

	ch := make(chan string)

	ip := make(net.IP, net.IPv4len)
	ip[0] = byte(start >> 24)
	ip[1] = byte(start >> 16)
	ip[2] = byte(start >> 8)
	ip[3] = byte(start)

	var i byte
	go func() {
		for i = 0; i < finB-startB; i++ {
			ip[1] = startB + i
			ch <- ip.String()
		}
		close(ch)
	}()
	return ch
}
