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
func IpGenerator(target string) chan string {
	start, fin := GetIpRange(target)
	ch := make(chan string)
	var i uint
	go func() {
		for i = 0; i <= fin - start; i++ {
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

//func GenIPC(alive []string, AliveNum int) chan string {
//	Tchan := make(chan string)
//	var target string
//	for _, v := range alive {
//		go func() {
//			for i := 0; i <= 256*AliveNum; i++ {
//				target = <-IpGenerator(v)
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
func BipGenerator(target string) chan string {
	start, fin := GetIpRange(target)
	startB := byte(start >> 16)
	finB := byte((fin + 1) >> 16)

	ch := make(chan string)

	ip := net.ParseIP(Int2IP(start)).To4()

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
