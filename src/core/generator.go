package core

import (
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
	"sync"
)

func ip2int(ip string) uint {
	s2ip := net.ParseIP(ip).To4()
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

func getMaskRange(mask int) (before uint, after uint) {

	before = uint(math.Pow(2, 32) - math.Pow(2, float64(32-mask)))
	after = uint(math.Pow(2, float64(32-mask)) - 1)
	return before, after
}

func getIpRange(target string) (start uint, fin uint) {
	_, cidr, _ := net.ParseCIDR(target)
	mask, _ := cidr.Mask.Size()
	before, after := getMaskRange(mask)
	ipint := ip2int(cidr.IP.String())

	start = ipint & before
	fin = ipint | after
	return start, fin
}

//使用管道生成IP
func defaultIpGenerator(CIDR string, ch chan string) chan string {
	start, fin := getIpRange(CIDR)
	for i := start; i <= fin; i++ {
		// 如果是广播地址或网络地址,则跳过
		if (i)%256 != 255 && (i)%256 != 0 {
			ch <- int2ip(i)
		}
		if i%65535 == 0 {
			processLog(fmt.Sprintf("[*] Processing CIDR: %s/16", int2ip(i)))
		}
	}
	return ch
}

func goDefaultIpGenerator(CIDR string) chan string {
	start, fin := getIpRange(CIDR)
	ch := make(chan string)
	go func() {
		for i := start; i <= fin; i++ {
			// 如果是广播地址或网络地址,则跳过
			if (i)%256 != 255 && (i)%256 != 0 {
				ch <- int2ip(i)
			}
		}
		close(ch)
	}()
	return ch
}

//此处的生成方式是每个C段交替生成,1.1,2.1....1.255,2.255这样
func smartIpGenerator(CIDR string, ch chan string, temp *sync.Map) chan string {
	start, fin := getIpRange(CIDR)
	var outIP string
	var C, B uint

	for C = 1; C < 255; C++ {
		for B = 0; B <= (fin-start)/256; B++ {
			outIP = int2ip(start + 256*B + C)
			if isnotAlive(int2ip(start+256*B), temp) {
				ch <- outIP
			}
		}
	}
	return ch
}

func goIPsGenerator(config Config) chan string {
	var ch = make(chan string)
	go func() {
		for _, cidr := range config.IPlist {
			processLog("[*] Processing CIDR:" + cidr)
			ch = defaultIpGenerator(cidr, ch)
			// 每个c段同步数据到文件
			_ = FileHandle.Sync()
		}
		close(ch)
	}()
	return ch
}

func isnotAlive(ip string, temp *sync.Map) bool {
	_, ok := temp.Load(ip)
	return !ok
}

func getMask(cidr string) int {
	mask, _ := strconv.Atoi(strings.Split(cidr, "/")[1])
	return mask
}

func aIpGenerator(CIDR string, ipps []uint, ch chan string, temp *sync.Map) chan string {
	start, fin := getIpRange(CIDR)
	//ch := make(chan string)
	startb := start / 65536 % 256
	finb := fin / 65536 % 256
	var c, b uint
	//go func() {
	for c = 0; c < 255; c++ {
		for b = 0; b <= finb-startb; b++ {
			//println(int2ip(start + b*65536 + c*256 + 1))
			//ip := int2ip(start + b*65536 + c + 1)
			if isnotAlive(int2ip(start+b*65536+256), temp) {
				//println(int2ip(start + b*65536 + c*256 + 1))
				for _, p := range ipps {
					ch <- int2ip(start + b*65536 + c*256 + p)
				}
			}
		}
	}
	//	close(ch)
	//}()

	return ch
}

func firstInterGenerator(ch chan string) chan string {
	fmt.Println("[*] Spraying : 10.0.0.0/8")
	ch = firstIpGenerator("10.0.0.0/8", ch)
	fmt.Println("[*] Spraying : 172.16.0.0/12")
	ch = firstIpGenerator("172.16.0.0/12", ch)
	fmt.Println("[*] Spraying : 192.168.0.0/16")
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

func ipGenerator(config Config, temp *sync.Map) chan string {
	ch := make(chan string)
	mask := getMask(config.IP)
	go func() {
		if config.Mod == "s" {
			ch = smartIpGenerator(config.IP, ch, temp)
		} else if config.Mod == "ss" {
			if mask < 16 {
				ch = aIpGenerator(config.IP, config.IpProbeList, ch, temp)
			} else {
				ch = smartIpGenerator(config.IP, ch, temp)
			}
		} else if config.Mod == "f" {
			ch = firstIpGenerator(config.IP, ch)
		} else {
			ch = defaultIpGenerator(config.IP, ch)
		}
		close(ch)
	}()
	return ch
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

func generator(config Config) chan TargetConfig {
	var ch chan string
	targetChannel := make(chan TargetConfig)
	var tc TargetConfig
	go func() {
		if config.Spray {
			// 端口喷洒
			for _, port := range config.Portlist {
				processLog("[*] Processing port:" + port)
				if config.IPlist != nil {
					for _, cidr := range config.IPlist {
						ch = goDefaultIpGenerator(cidr)
						for ip := range ch {
							tc.ip = ip
							tc.port = port
							targetChannel <- tc
						}
						_ = FileHandle.Sync()
					}
				} else {
					ch = goDefaultIpGenerator(config.IP)
					for ip := range ch {
						tc.ip = ip
						tc.port = port
						targetChannel <- tc
					}
				}
			}
		} else {
			// 默认模式
			// 批量处理
			if config.IPlist != nil {
				if config.IPlist != nil {
					ch = goIPsGenerator(config)
				}
			} else {
				ch = goDefaultIpGenerator(config.IP)
			}
			for ip := range ch {
				for _, port := range config.Portlist {
					tc.ip = ip
					tc.port = port
					targetChannel <- tc
				}
			}
		}
		close(targetChannel)
	}()
	return targetChannel
}

func checkIp(CIDR string) string {
	fmtip := getIp(strings.Split(CIDR, "/")[0])
	if fmtip != "" {
		return fmtip + "/" + strings.Split(CIDR, "/")[1]
	}
	fmt.Println("[-] CIRD cannot find host:" + CIDR + "'s ip address")
	return ""
}

func isIPv4(ip string) bool {
	address := net.ParseIP(ip).To4()
	if address != nil {
		return true
	}
	return false
}
