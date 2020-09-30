package moudle

import (
	"math"
	"net"
	"strconv"
	"strings"
)

var blacklist = make(map[uint32]bool)
var temp = make([]int, 256)

func MyIP2Int(ipmask string) uint32 {
	ParseIP := strings.Split(ipmask, "/")

	ip := ParseIP[0]

	s2ip := net.ParseIP(ip).To4()

	return uint32(s2ip[3]) | uint32(s2ip[2])<<8 | uint32(s2ip[1])<<16 | uint32(s2ip[0])<<24
}

func MyInt2IP(ipint uint32) string {
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

func GenIP(target string) chan string {
	start, fin := HandleIPAMASK(target)
	ch := make(chan string)
	sum := fin - start
	var i uint32
	go func() {
		for i = 0; i <= sum; i++ {

			ch <- MyInt2IP(i + start)
		}
		close(ch)
	}()
	return ch
}

func GenIP2(target string) chan string {
	start, _ := HandleIPAMASK(target)
	ch := make(chan string)
	var outIP string
	//sum := fin -start
	var i, j uint32

	go func() {
		for i = 0; i < 256; i++ {
			for j = 0; j < 256; j++ {
				outIP = MyInt2IP(start + 256*j + i)
				if IPifNeed2(outIP) {
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

//func GenIPC2(alive []string) chan string{
//
//}

func GenTarget(ch chan string, portlist []string) chan string {
	Tchan := make(chan string)

	go func() {
		for i := range ch {
			for _, v := range portlist {
				Tchan <- i + ":" + v
			}
		}
		close(Tchan)
	}()
	return Tchan
}

func HandleIPAMASK(server string) (start uint32, fin uint32) {
	mask := strings.Split(server, "/")[1]

	before, after := HandleMask(mask)

	ipint := MyIP2Int(server)

	start = ipint & before
	fin = ipint | after
	return start, fin
}

func IPifNeed(ip string) bool {
	ip = ip + "/24"
	start, _ := HandleIPAMASK(ip)
	if _, ok := blacklist[start]; ok {
		return false
	}
	return true
}

func IPifNeed2(ip string) bool {
	s2ip := net.ParseIP(ip).To4()
	c := s2ip[2]
	if temp[c] > 0 {
		return false
	}
	return true
}

func GetMap() map[uint32]bool {
	return blacklist
}

func GetSlice() []int {
	return temp
}
