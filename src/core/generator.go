package core

import (
	"fmt"
	. "getitle/src/utils"
	"sync"
)

//使用管道生成IP
func defaultIpGenerator(CIDR string, ch chan string) chan string {
	start, fin := getIpRange(CIDR)
	for i := start; i <= fin; i++ {
		// 如果是广播地址或网络地址,则跳过
		if (i)%256 != 255 && (i)%256 != 0 {
			ch <- int2ip(i)
		}
		if i%65535 == 0 {
			progressLogln(fmt.Sprintf("[*] Processing CIDR: %s/16", int2ip(i)))
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

func goIPsGenerator(iplist []string) chan string {
	var ch = make(chan string)
	go func() {
		for _, cidr := range iplist {
			tmpalive := Opt.AliveSum
			ch = defaultIpGenerator(cidr, ch)
			if getMask(cidr) != 32 {
				progressLogln(fmt.Sprintf("[*] Processed CIDR: %s, found %d ports", cidr, Opt.AliveSum-tmpalive))
			}
			// 每个c段同步数据到文件
			fileFlush()
		}
		close(ch)
	}()
	return ch
}

func isnotAlive(ip string, temp *sync.Map) bool {
	_, ok := temp.Load(ip)
	return !ok
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
	progressLogln("[*] Spraying : 10.0.0.0/8")
	ch = firstIpGenerator("10.0.0.0/8", ch)
	progressLogln("[*] Spraying : 172.16.0.0/12")
	ch = firstIpGenerator("172.16.0.0/12", ch)
	progressLogln("[*] Spraying : 192.168.0.0/16")
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

func ipGenerator(ip, mod string, ipl []uint, temp *sync.Map) chan string {
	ch := make(chan string)
	mask := getMask(ip)
	go func() {
		switch mod {
		case "s", "sb":
			ch = smartIpGenerator(ip, ch, temp)
		case "ss", "sc":
			if mask < 16 {
				ch = aIpGenerator(ip, ipl, ch, temp)
			} else {
				ch = smartIpGenerator(ip, ch, temp)
			}
		case "f":
			ch = firstIpGenerator(ip, ch)
		default:
			ch = defaultIpGenerator(ip, ch)
		}
		close(ch)
	}()
	return ch
}

func tcGenerator(ch chan string, portlist []string) chan targetConfig {
	targetChannel := make(chan targetConfig)
	var tc targetConfig
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

func generator(targets interface{}, config Config) chan targetConfig {
	targetChannel := make(chan targetConfig)
	go func() {
		switch targets.(type) {
		case Results:
			genFromResults(targets.(Results), &targetChannel)
		default:
			if config.Spray { // 端口喷洒
				genFromSpray(targets, config.Portlist, &targetChannel)
			} else { // 默认模式 批量处理
				genFromDefault(targets, config.Portlist, &targetChannel)
			}
		}
		close(targetChannel)
	}()
	return targetChannel
}

func genFromResults(results Results, tcch *chan targetConfig) {
	for _, result := range results {
		*tcch <- targetConfig{result.Ip, result.Port, result.Frameworks}
	}
}

func genFromSpray(targets interface{}, portlist []string, tcch *chan targetConfig) {
	var ch chan string
	for _, port := range portlist {
		tmpalive := Opt.AliveSum
		switch targets.(type) {
		case []string:
			for _, cidr := range targets.([]string) {
				ch = goDefaultIpGenerator(cidr)
				for ip := range ch {
					*tcch <- targetConfig{ip, port, nil} // finger适配
				}
				fileFlush()
			}
		default:
			ch = goDefaultIpGenerator(targets.(string))
			for ip := range ch {
				*tcch <- targetConfig{ip, port, nil}
			}
		}
		progressLogln(fmt.Sprintf("[*] Processed Port: %s, found %d ports", port, Opt.AliveSum-tmpalive))
	}
}

func genFromDefault(targets interface{}, portlist []string, tcch *chan targetConfig) {
	var ch chan string
	switch targets.(type) {
	case []string:
		ch = goIPsGenerator(targets.([]string))
	default:
		ch = goDefaultIpGenerator(targets.(string))
	}
	for ip := range ch {
		for _, port := range portlist {
			*tcch <- targetConfig{ip, port, nil}
		}
	}
}
