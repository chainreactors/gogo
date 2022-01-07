package core

import (
	"fmt"
	. "getitle/src/utils"
	"sync"
)

func NewIpGenerator(config Config) *IpGenerator {
	var alivemap sync.Map
	gen := IpGenerator{
		alivedmap: &alivemap,
		ip_probe:  config.IpProbeList,
	}
	return &gen
}

type IpGenerator struct {
	count     int
	ch        chan string
	alivedmap *sync.Map
	ip_probe  []uint
}

func (gen *IpGenerator) defaultIpGenerator(CIDR string) {
	start, fin := getIpRange(CIDR)
	for i := start; i <= fin; i++ {
		// 如果是广播地址或网络地址,则跳过
		if (i)%256 != 255 && (i)%256 != 0 {
			gen.ch <- int2ip(i)
		}
		if i%65535 == 0 {
			progressLogln(fmt.Sprintf("[*] Processing CIDR: %s/16", int2ip(i)))
		}
	}
}

func (gen *IpGenerator) smartIpGenerator(cidr string) {
	start, fin := getIpRange(cidr)
	var outIP string
	var C, B uint

	for C = 1; C < 255; C++ {
		for B = 0; B <= (fin-start)/256; B++ {
			outIP = int2ip(start + 256*B + C)
			if isnotAlive(int2ip(start+256*B), gen.alivedmap) {
				gen.ch <- outIP
			}
		}
	}
}

func (gen *IpGenerator) IPsGenerator(ips []string) {
	for _, cidr := range ips {
		tmpalive := Opt.AliveSum
		gen.defaultIpGenerator(cidr)
		if getMask(cidr) != 32 {
			progressLogln(fmt.Sprintf("[*] Processed CIDR: %s, found %d ports", cidr, Opt.AliveSum-tmpalive))
		}
		// 每个c段同步数据到文件
		fileFlush()
	}
}

func (gen *IpGenerator) aIPgenerator(cidr string) {
	start, fin := getIpRange(cidr)
	//ch := make(chan string)
	startb := start / 65536 % 256
	finb := fin / 65536 % 256
	var c, b uint
	//go func() {
	for c = 0; c < 255; c++ {
		for b = 0; b <= finb-startb; b++ {
			//println(int2ip(start + b*65536 + c*256 + 1))
			//ip := int2ip(start + b*65536 + c + 1)
			if isnotAlive(int2ip(start+b*65536+256), gen.alivedmap) {
				//println(int2ip(start + b*65536 + c*256 + 1))
				for _, p := range gen.ip_probe {
					gen.ch <- int2ip(start + b*65536 + c*256 + p)
				}
			}
		}
	}
}

func (gen *IpGenerator) Generate(target interface{}, mod string) chan string {
	gen.ch = make(chan string)

	go func() {
		switch target.(type) {
		case []string:
			cidrs := target.([]string)
			gen.IPsGenerator(cidrs)
		default:
			cidr := target.(string)
			mask := getMask(cidr)
			switch mod {
			case "s", "sb":
				if mask < 24 {
					gen.smartIpGenerator(cidr)
				} else {
					gen.defaultIpGenerator(cidr)
				}
			case "ss", "sc":
				if mask < 16 {
					gen.aIPgenerator(cidr)
				} else if mask >= 16 && mask < 24 {
					gen.smartIpGenerator(cidr)
				} else {
					gen.defaultIpGenerator(cidr)
				}
			default:
				gen.defaultIpGenerator(cidr)
			}
		}
		close(gen.ch)
	}()
	return gen.ch
}

////使用管道生成IP
//func defaultIpGenerator(CIDR string, ch chan string) chan string {
//	start, fin := getIpRange(CIDR)
//	for i := start; i <= fin; i++ {
//		// 如果是广播地址或网络地址,则跳过
//		if (i)%256 != 255 && (i)%256 != 0 {
//			ch <- int2ip(i)
//		}
//		if i%65535 == 0 {
//			progressLogln(fmt.Sprintf("[*] Processing CIDR: %s/16", int2ip(i)))
//		}
//	}
//	return ch
//}

//func goDefaultIpGenerator(CIDR string) chan string {
//	start, fin := getIpRange(CIDR)
//	ch := make(chan string)
//	go func() {
//		for i := start; i <= fin; i++ {
//			// 如果是广播地址或网络地址,则跳过
//			if (i)%256 != 255 && (i)%256 != 0 {
//				ch <- int2ip(i)
//			}
//		}
//		close(ch)
//	}()
//	return ch
//}
//
////此处的生成方式是每个C段交替生成,1.1,2.1....1.255,2.255这样
//func smartIpGenerator(CIDR string, ch chan string, temp *sync.Map) chan string {
//	start, fin := getIpRange(CIDR)
//	var outIP string
//	var C, B uint
//
//	for C = 1; C < 255; C++ {
//		for B = 0; B <= (fin-start)/256; B++ {
//			outIP = int2ip(start + 256*B + C)
//			if isnotAlive(int2ip(start+256*B), temp) {
//				ch <- outIP
//			}
//		}
//	}
//	return ch
//}
//
//func goIPsGenerator(iplist []string) chan string {
//	var ch = make(chan string)
//	go func() {
//		for _, cidr := range iplist {
//			tmpalive := Opt.AliveSum
//			ch = defaultIpGenerator(cidr, ch)
//			if getMask(cidr) != 32 {
//				progressLogln(fmt.Sprintf("[*] Processed CIDR: %s, found %d ports", cidr, Opt.AliveSum-tmpalive))
//			}
//			// 每个c段同步数据到文件
//			fileFlush()
//		}
//		close(ch)
//	}()
//	return ch
//}

func isnotAlive(ip string, temp *sync.Map) bool {
	_, ok := temp.Load(ip)
	return !ok
}

//func aIpGenerator(CIDR string, ipps []uint, ch chan string, temp *sync.Map) chan string {
//	start, fin := getIpRange(CIDR)
//	//ch := make(chan string)
//	startb := start / 65536 % 256
//	finb := fin / 65536 % 256
//	var c, b uint
//	//go func() {
//	for c = 0; c < 255; c++ {
//		for b = 0; b <= finb-startb; b++ {
//			//println(int2ip(start + b*65536 + c*256 + 1))
//			//ip := int2ip(start + b*65536 + c + 1)
//			if isnotAlive(int2ip(start+b*65536+256), temp) {
//				//println(int2ip(start + b*65536 + c*256 + 1))
//				for _, p := range ipps {
//					ch <- int2ip(start + b*65536 + c*256 + p)
//				}
//			}
//		}
//	}
//	//	close(ch)
//	//}()
//
//	return ch
//}
//
//func ipGenerator(ip, mod string, ipl []uint, temp *sync.Map) chan string {
//	ch := make(chan string)
//	mask := getMask(ip)
//	go func() {
//		switch mod {
//		case "s", "sb":
//			ch = smartIpGenerator(ip, ch, temp)
//		case "ss", "sc":
//			if mask < 16 {
//				ch = aIpGenerator(ip, ipl, ch, temp)
//			} else {
//				ch = smartIpGenerator(ip, ch, temp)
//			}
//		default:
//			ch = defaultIpGenerator(ip, ch)
//		}
//		close(ch)
//	}()
//	return ch
//}

func NewTargetGenerator(config Config) *targetGenerator {
	gen := targetGenerator{
		ip_generator: NewIpGenerator(config),
		spray:        config.Spray,
	}
	return &gen
}

type targetGenerator struct {
	count        int
	spray        bool
	ch           chan targetConfig
	ip_generator *IpGenerator
}

func (gen *targetGenerator) genFromDefault(targets interface{}, portlist []string) {
	ch := gen.ip_generator.Generate(targets, "default")
	for ip := range ch {
		for _, port := range portlist {
			gen.ch <- targetConfig{ip, port, nil}
		}
	}
}

func (gen *targetGenerator) genFromSpray(targets interface{}, portlist []string) {
	var ch chan string
	for _, port := range portlist {
		tmpalive := Opt.AliveSum
		switch targets.(type) {
		case []string:
			for _, cidr := range targets.([]string) {
				ch = gen.ip_generator.Generate(cidr, "default")
				for ip := range ch {
					gen.ch <- targetConfig{ip, port, nil} // finger适配
				}
				fileFlush()
			}
		default:
			ch = gen.ip_generator.Generate(targets.(string), "default")
			for ip := range ch {
				gen.ch <- targetConfig{ip, port, nil}
			}
		}
		progressLogln(fmt.Sprintf("[*] Processed Port: %s, found %d ports", port, Opt.AliveSum-tmpalive))
	}
}

func (gen *targetGenerator) generator(targets interface{}, portlist []string) chan targetConfig {
	gen.ch = make(chan targetConfig)
	go func() {
		switch targets.(type) {
		case Results:
			//genFromResults(targets.(Results), &targetChannel)
		default:
			if gen.spray { // 端口喷洒
				gen.genFromSpray(targets, portlist)
			} else { // 默认模式 批量处理
				gen.genFromDefault(targets, portlist)
			}
		}
		close(gen.ch)
	}()

	return gen.ch
}

func (gen *targetGenerator) smartGenerator(targets string, portlist []string, mod string) chan targetConfig {
	gen.ch = make(chan targetConfig)

	go func() {
		ch := gen.ip_generator.Generate(targets, mod)
		for ip := range ch {
			for _, port := range portlist {
				gen.ch <- targetConfig{ip: ip, port: port}
			}
		}
		close(gen.ch)
	}()
	return gen.ch
}

//func (gen *targetGenerator) generate(config Config) chan targetConfig  {
//	targetGen := NewTargetGenerator(config)
//}

//func tcGenerator(ch chan string, portlist []string) chan targetConfig {
//	targetChannel := make(chan targetConfig)
//	go func() {
//		for ip := range ch {
//			for _, port := range portlist {
//				targetChannel <- targetConfig{ip:ip,port:port}
//			}
//		}
//		close(targetChannel)
//	}()
//	return targetChannel
//}

//func generator(targets interface{}, config Config) chan targetConfig {
//targetChannel := make(chan targetConfig)
//go func() {
//	tcgen := NewTargetGenerator(config)
//	switch targets.(type) {
//	case Results:
//		genFromResults(targets.(Results), &targetChannel)
//	default:
//		if config.Spray { // 端口喷洒
//			genFromSpray(targets, config.Portlist, &targetChannel)
//		} else { // 默认模式 批量处理
//			genFromDefault(targets, config.Portlist, &targetChannel)
//		}
//	}
//ipgen := NewIpGenerator(config)
//ipgen.Generate(config.IP, config.Mod)
//for ip := range ipgen.ch {
//	for _, port := range config.Portlist {
//		targetChannel <- targetConfig{ip, port, nil}
//	}
//}
//switch targets.(type) {
//case Results:
//	genFromResults(targets.(Results), &targetChannel)
//default:
//	if config.Spray { // 端口喷洒
//		genFromSpray(targets, config.Portlist, &targetChannel)
//	} else { // 默认模式 批量处理
//		genFromDefault(targets, config.Portlist, &targetChannel)
//	}
//}
//close(targetChannel)
//}()
//return targetChannel
//}

//func genFromResults(results Results, tcch *chan targetConfig) {
//	for _, result := range results {
//		*tcch <- targetConfig{result.Ip, result.Port, result.Frameworks}
//	}
//}
//
//func genFromSpray(targets interface{}, portlist []string, tcch *chan targetConfig) {
//	var ch chan string
//	for _, port := range portlist {
//		tmpalive := Opt.AliveSum
//		switch targets.(type) {
//		case []string:
//			for _, cidr := range targets.([]string) {
//				ch = goDefaultIpGenerator(cidr)
//				for ip := range ch {
//					*tcch <- targetConfig{ip, port, nil} // finger适配
//				}
//				fileFlush()
//			}
//		default:
//			ch = goDefaultIpGenerator(targets.(string))
//			for ip := range ch {
//				*tcch <- targetConfig{ip, port, nil}
//			}
//		}
//		progressLogln(fmt.Sprintf("[*] Processed Port: %s, found %d ports", port, Opt.AliveSum-tmpalive))
//	}
//}
//
//func genFromDefault(targets interface{}, portlist []string, tcch *chan targetConfig) {
//	var ch chan string
//	switch targets.(type) {
//	case []string:
//		ch = goIPsGenerator(targets.([]string))
//	default:
//		ch = goDefaultIpGenerator(targets.(string))
//	}
//	for ip := range ch {
//		for _, port := range portlist {
//			*tcch <- targetConfig{ip, port, nil}
//		}
//	}
//}
