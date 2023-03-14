package core

import (
	"github.com/chainreactors/gogo/v2/internal/plugin"
	. "github.com/chainreactors/gogo/v2/pkg"
	. "github.com/chainreactors/logs"
	"github.com/chainreactors/parsers"
	"github.com/chainreactors/utils"
	"strings"
	"sync"
)

func NewIpGenerator(config Config) *IpGenerator {
	var alivemap sync.Map
	gen := IpGenerator{
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
}

func (gen *IpGenerator) defaultIpGenerator(cidr *utils.CIDR) {
	for ip := range cidr.Range() {
		if ip.Ver == 6 {
			gen.ch <- "[" + ip.String() + "]"
		} else {
			gen.ch <- ip.String()
		}
	}
}

func (gen *IpGenerator) smartIpGenerator(cidr *utils.CIDR) {
	cs, err := cidr.Split(24)
	if err != nil {
		return
	}
	ccs := make(map[string]*utils.CIDR)
	for _, c := range cs {
		ccs[c.String()] = c
	}

	for i := 0; i < 256; i++ {
		for s, c := range ccs {
			if isnotAlive(s, gen.alivedMap) {
				//println(c.Next().String())
				gen.ch <- c.Next().String()
			}
		}
	}
}

func (gen *IpGenerator) sSmartGenerator(cidr *utils.CIDR) {
	bcs, err := cidr.Split(16)
	if err != nil {
		return
	}

	ccs := make(map[string]utils.CIDRs)
	for _, b := range bcs {
		tmp, _ := b.Split(24)
		ccs[b.String()] = tmp
	}

	var count int
	for i := 0; i < 256; i++ {
		for b, c := range ccs {
			ip := c[i].Next()
			for _, p := range gen.ipProbe {
				count++
				tip := ip.Copy()
				tip.IP[3] = byte(p)
				if isnotAlive(b, gen.alivedMap) {
					gen.ch <- ip.String()
				}
			}
		}
	}
	println(count)
}

func (gen *IpGenerator) generatorDispatch(cidr *utils.CIDR, mod string) chan string {
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

func NewTargetGenerator(config Config) *TargetGenerator {
	gen := TargetGenerator{
		ipGenerator: NewIpGenerator(config),
		spray:       config.PortSpray,
		hostsMap:    config.HostsMap,
	}
	return &gen
}

type TargetGenerator struct {
	count       int
	spray       bool
	ch          chan targetConfig
	hostsMap    map[string][]string
	ipGenerator *IpGenerator
}

func (gen *TargetGenerator) genFromDefault(cidrs utils.CIDRs, portlist []string) {
	for _, cidr := range cidrs {
		tmpalived := Opt.AliveSum
		ch := gen.ipGenerator.generatorDispatch(cidr, Default)
		for ip := range ch {
			for _, port := range portlist {
				gen.ch <- targetConfig{ip: ip, port: port, hosts: gen.hostsMap[ip]}
				if plugin.RunOpt.Sum%65535 == 65534 {
					Log.Importantf("Current processing %s:%s, number: %d", ip, port, plugin.RunOpt.Sum)
				}
			}
		}
		if cidr.Count() > 1 {
			Log.Importantf("Scanned %s with %d ports, found %d ports", cidr.String(), len(portlist), Opt.AliveSum-tmpalived)
		}
		syncFile()
	}
}

func (gen *TargetGenerator) genFromSpray(cidrs utils.CIDRs, portlist []string) {
	//gen.ch = make(chan string)
	var tmpPorts []string
	for _, port := range portlist {
		tmpalive := Opt.AliveSum

		for _, cidr := range cidrs {
			ch := gen.ipGenerator.generatorDispatch(cidr, Default)
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
			if len(tmpPorts) > 10 {
				Log.Importantf("Processed Port: %s, found %d ports", strings.Join(tmpPorts[:10], ",")+"......, "+port, Opt.AliveSum-tmpalive)
			} else {
				Log.Importantf("Processed Port: %s, found %d ports", strings.Join(tmpPorts, ","), Opt.AliveSum-tmpalive)
			}
			tmpPorts = []string{}
		}
	}
}

func (gen *TargetGenerator) genFromResult(results parsers.GOGOResults) {
	for _, result := range results {
		gen.ch <- targetConfig{ip: result.Ip, port: result.Port, fingers: result.Frameworks}
	}
}

func (gen *TargetGenerator) generatorDispatch(targets interface{}, portlist []string) chan targetConfig {
	gen.ch = make(chan targetConfig)
	go func() {
		switch targets.(type) {
		case parsers.GOGOResults:
			gen.genFromResult(targets.(parsers.GOGOResults))
		default:
			if gen.spray { // 端口喷洒
				gen.genFromSpray(targets.(utils.CIDRs), portlist)
			} else { // 默认模式 批量处理
				gen.genFromDefault(targets.(utils.CIDRs), portlist)
			}
		}
		close(gen.ch)
	}()

	return gen.ch
}

func (gen *TargetGenerator) smartGenerator(cidr *utils.CIDR, portlist []string, mod string) chan targetConfig {
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
