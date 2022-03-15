package core

import (
	"fmt"
	. "getitle/src/pkg"
	"sync"
)

func NewIpGenerator(config Config) *IpGenerator {
	var alivemap sync.Map
	gen := IpGenerator{
		excludeIP: config.ExcludeMap,
		alivedMap: &alivemap,
		ipProbe:   config.IpProbeList,
	}
	return &gen
}

type IpGenerator struct {
	count     int
	ch        chan string
	alivedMap *sync.Map
	ipProbe   []uint
	excludeIP map[uint]bool
}

func (gen *IpGenerator) defaultIpGenerator(CIDR string) {
	start, fin := getIpRange(CIDR)
	for i := start; i <= fin; i++ {
		// 如果是广播地址或网络地址,则跳过
		if (i)%256 != 255 && (i)%256 != 0 && !gen.excludeIP[i] {
			gen.ch <- Int2Ip(i)
		}
		if i%65536 == 0 {
			Log.Logging(fmt.Sprintf("[*] Processing CIDR: %s/16", Int2Ip(i)))
		}
	}
}

func (gen *IpGenerator) smartIpGenerator(cidr string) {
	start, fin := getIpRange(cidr)
	var outIP string
	var C, B uint

	for C = 1; C < 255; C++ {
		for B = 0; B <= (fin-start)/256; B++ {
			outIP = Int2Ip(start + 256*B + C)
			if isnotAlive(Int2Ip(start+256*B), gen.alivedMap) && !gen.excludeIP[start+256*B+C] {
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
			Log.Logging(fmt.Sprintf("[*] Processed CIDR: %s, found %d ports", cidr, Opt.AliveSum-tmpalive))
		}
		Opt.File.Sync()
	}
}

func (gen *IpGenerator) sSmartGenerator(cidr string) {
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
			if isnotAlive(Int2Ip(start+b*65536+256), gen.alivedMap) {
				//println(int2ip(start + b*65536 + c*256 + 1))
				for _, p := range gen.ipProbe {
					if !gen.excludeIP[start+b*65536+c*256+p] {
						gen.ch <- Int2Ip(start + b*65536 + c*256 + p)
					}
				}
			}
		}
	}
}

func (gen *IpGenerator) generate(target interface{}, mod string) chan string {
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
				if mask <= 24 {
					gen.smartIpGenerator(cidr)
				} else {
					gen.defaultIpGenerator(cidr)
				}
			case "ss", "sc":
				if mask <= 16 {
					gen.sSmartGenerator(cidr)
				} else if mask > 16 && mask <= 24 {
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

func isnotAlive(ip string, temp *sync.Map) bool {
	_, ok := temp.Load(ip)
	return !ok
}

func NewTargetGenerator(config Config) *targetGenerator {
	gen := targetGenerator{
		ip_generator: NewIpGenerator(config),
		spray:        config.PortSpray,
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
	ch := gen.ip_generator.generate(targets, "default")
	for ip := range ch {
		for _, port := range portlist {
			gen.ch <- targetConfig{ip: ip, port: port}
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
				ch = gen.ip_generator.generate(cidr, "default")
				for ip := range ch {
					gen.ch <- targetConfig{ip: ip, port: port}
				}
				Opt.File.Sync()
			}
		default:
			ch = gen.ip_generator.generate(targets.(string), "default")
			for ip := range ch {
				gen.ch <- targetConfig{ip: ip, port: port}
			}
		}
		Log.Logging(fmt.Sprintf("[*] Processed Port: %s, found %d ports", port, Opt.AliveSum-tmpalive))
	}
}

func (gen *targetGenerator) genFromResult(results Results) {
	for _, result := range results {
		gen.ch <- targetConfig{result.Ip, result.Port, result.HttpHost, result.Frameworks}
	}
}

func (gen *targetGenerator) generator(targets interface{}, portlist []string) chan targetConfig {
	gen.ch = make(chan targetConfig)
	go func() {
		switch targets.(type) {
		case Results:
			gen.genFromResult(targets.(Results))
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
		ch := gen.ip_generator.generate(targets, mod)
		for ip := range ch {
			for _, port := range portlist {
				gen.ch <- targetConfig{ip: ip, port: port}
			}
		}
		close(gen.ch)
	}()
	return gen.ch
}
