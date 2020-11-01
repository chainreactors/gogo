package moudle

import (
	"math"
	"net"
	"strconv"
	"strings"
)

var blacklist = make(map[uint32]bool)

func Ip2Int(ipmask string) uint32 {
	ParseIP := strings.Split(ipmask, "/")
	ip := ParseIP[0]
	s2ip := net.ParseIP(ip).To4()
	return uint32(s2ip[3]) | uint32(s2ip[2])<<8 | uint32(s2ip[1])<<16 | uint32(s2ip[0])<<24
}

func Int2IP(ipint uint32) string {
	ip := make(net.IP, net.IPv4len)
	ip[0] = byte(ipint >> 24)
	ip[1] = byte(ipint >> 16)
	ip[2] = byte(ipint >> 8)
	ip[3] = byte(ipint)
	return ip.String()
}

func HandleMask(mask string) (before uint32, after uint32) {
	IntMask, _ := strconv.Atoi(mask)

	before = uint32(math.Pow(2, 32) - math.Pow(2, float64(32-IntMask)))

	after = uint32(math.Pow(2, float64(32-IntMask)) - 1)

	return before, after
}

//使用管道生成IP
func GenIP(target string) chan string {
	start, fin := HandleIPAMASK(target)
	ch := make(chan string)
	sum := fin - start
	var i uint32
	go func() {
		for i = 0; i <= sum; i++ {
			ch <- Int2IP(i + start)
		}
		close(ch)
	}()
	return ch
}

//此处的生成方式是每个C段交替生成,1.1,2.1....1.255,2.255这样
func GenIP2(target string, temp []int) chan string {
	start, _ := HandleIPAMASK(target)
	ch := make(chan string)
	var outIP string
	//sum := fin -start
	var i, j uint32

	go func() {
		for i = 0; i < 256; i++ {
			for j = 0; j < 256; j++ {
				outIP = Int2IP(start + 256*j + i)
				if IPifNeed2(outIP, temp) {
					ch <- outIP
				} else {
					continue
				}

			}
		}
		close(ch)
	}()
	return ch
}

func GenIPC(alive []string, AliveNum int) chan string {
	Tchan := make(chan string)
	var target string
	for _, v := range alive {
		go func() {
			for i := 0; i <= 256*AliveNum; i++ {
				target = <-GenIP(v)
				Tchan <- target
			}
			close(Tchan)

		}()
		return Tchan
	}
	return Tchan
}

func GenTarget(ch chan string, portlist []string) chan string {
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

func HandleIPAMASK(server string) (start uint32, fin uint32) {
	mask := strings.Split(server, "/")[1]

	before, after := HandleMask(mask)

	ipint := Ip2Int(server)

	start = ipint & before
	fin = ipint | after
	return start, fin
}

func IPifNeed2(ip string, temp []int) bool {
	s2ip := net.ParseIP(ip).To4()
	c := s2ip[2]
	if temp[c] > 0 {
		return false
	}
	return true
}

func GenBIP(target string) chan string {
	start, fin := HandleIPAMASK(target)
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
