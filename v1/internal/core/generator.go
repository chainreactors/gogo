package core

import (
	. "github.com/chainreactors/gogo/v1/pkg"
	"github.com/chainreactors/ipcs"
	. "github.com/chainreactors/logs"
	"strings"
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

func (gen *IpGenerator) defaultIpGenerator(cidr *ipcs.CIDR) {
	start, fin := cidr.Range()
	for i := start; i <= fin; i++ {
		// 如果是广播地址或网络地址,则跳过
		if (i)%256 != 255 && (i)%256 != 0 && !gen.excludeIP[i] {
			gen.ch <- ipcs.Int2Ip(i)
		}
		if i%65536 == 0 {
			Log.Importantf("Processing CIDR: %s/16", ipcs.Int2Ip(i))
		}
	}
}

func (gen *IpGenerator) smartIpGenerator(cidr *ipcs.CIDR) {
	start, fin := cidr.Range()
	var outIP string
	var C, B uint

	for C = 1; C < 255; C++ {
		for B = 0; B <= (fin-start)/256; B++ {
			outIP = ipcs.Int2Ip(start + 256*B + C)
			//if isnotAlive(ipcs.Int2Ip(start+256*B), gen.alivedMap) && !gen.excludeIP[start+256*B+C] {
			if isnotAlive(ipcs.Int2Ip(start+256*B), gen.alivedMap) {
				gen.ch <- outIP
			}
		}
	}
}

//func (gen *IpGenerator) IPsGenerator(ips []string) {
//	for _, cidr := range ips {
//		tmpalive := Opt.AliveSum
//		gen.defaultIpGenerator(cidr)
//		if getMask(cidr) != 32 {
//			Log.Importantf("Processed CIDR: %s, found %d ports", cidr, Opt.AliveSum-tmpalive)
//			syncFile()
//		}
//	}
//}

func (gen *IpGenerator) sSmartGenerator(cidr *ipcs.CIDR) {
	start, fin := cidr.Range()
	//ch := make(chan string)
	startb := start / 65536 % 256
	finb := fin / 65536 % 256
	var c, b uint
	//go func() {
	for c = 0; c < 255; c++ {
		for b = 0; b <= finb-startb; b++ {
			//println(int2ip(start + b*65536 + c*256 + 1))
			//ip := int2ip(start + b*65536 + c + 1)
			if isnotAlive(ipcs.Int2Ip(start+b*65536+256), gen.alivedMap) {
				//println(int2ip(start + b*65536 + c*256 + 1))
				for _, p := range gen.ipProbe {
					gen.ch <- ipcs.Int2Ip(start + b*65536 + c*256 + p)
					//if !gen.excludeIP[start+b*65536+c*256+p] {
					//
					//}
				}
			}
		}
	}
}

func (gen *IpGenerator) generatorDispatch(cidr *ipcs.CIDR, mod string) chan string {
	gen.ch = make(chan string)

	go func() {
		mask := cidr.Mask
		switch mod {
		case SMART, SUPERSMARTC:
			if mask <= 24 {
				gen.smartIpGenerator(cidr)
			}
		case SUPERSMART, SUPERSMARTB:
			if mask <= 16 {
				gen.sSmartGenerator(cidr)
			}
		default:
			gen.defaultIpGenerator(cidr)
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
		ipGenerator: NewIpGenerator(config),
		spray:       config.PortSpray,
		hostsMap:    config.HostsMap,
	}
	return &gen
}

type targetGenerator struct {
	count       int
	spray       bool
	ch          chan targetConfig
	hostsMap    map[string][]string
	ipGenerator *IpGenerator
}

func (gen *targetGenerator) genFromDefault(cidrs ipcs.CIDRs, portlist []string) {
	for _, cidr := range cidrs {
		tmpalived := Opt.AliveSum
		ch := gen.ipGenerator.generatorDispatch(cidr, "default")
		for ip := range ch {
			for _, port := range portlist {
				gen.ch <- targetConfig{ip: ip, port: port, hosts: gen.hostsMap[ip]}
			}
		}
		if cidr.Count() > 1 {
			Log.Importantf("Scanned %s with %d ports, found %d ports", cidr.String(), len(portlist), Opt.AliveSum-tmpalived)
		}
		syncFile()
	}
}

func (gen *targetGenerator) genFromSpray(cidrs ipcs.CIDRs, portlist []string) {
	//gen.ch = make(chan string)
	var tmpPorts []string
	for _, port := range portlist {
		tmpalive := Opt.AliveSum

		for _, cidr := range cidrs {
			ch := gen.ipGenerator.generatorDispatch(cidr, "default")
			for ip := range ch {
				gen.ch <- targetConfig{ip: ip, port: port, hosts: gen.hostsMap[ip]}
			}
			syncFile()
		}

		tmpPorts = append(tmpPorts, port)
		if Opt.AliveSum-tmpalive > 0 {
			if len(tmpPorts) >= 100 {
				tmpPorts = tmpPorts[:100]
			}
			Log.Importantf("Processed Port: %s, found %d ports", strings.Join(tmpPorts, ",")+"......, "+port, Opt.AliveSum-tmpalive)
			tmpPorts = []string{}
		}
	}
}

func (gen *targetGenerator) genFromResult(results Results) {
	for _, result := range results {
		gen.ch <- targetConfig{result.Ip, result.Port, result.HttpHosts, result.Frameworks}
	}
}

func (gen *targetGenerator) generatorDispatch(targets interface{}, portlist []string) chan targetConfig {
	gen.ch = make(chan targetConfig)
	go func() {
		switch targets.(type) {
		case Results:
			gen.genFromResult(targets.(Results))
		default:
			if gen.spray { // 端口喷洒
				gen.genFromSpray(targets.(ipcs.CIDRs), portlist)
			} else { // 默认模式 批量处理
				gen.genFromDefault(targets.(ipcs.CIDRs), portlist)
			}
		}
		close(gen.ch)
	}()

	return gen.ch
}

func (gen *targetGenerator) smartGenerator(cidr *ipcs.CIDR, portlist []string, mod string) chan targetConfig {
	gen.ch = make(chan targetConfig)

	go func() {
		ch := gen.ipGenerator.generatorDispatch(cidr, mod)
		for ip := range ch {
			for _, port := range portlist {
				gen.ch <- targetConfig{ip: ip, port: port}
			}
		}
		close(gen.ch)
	}()
	return gen.ch
}
