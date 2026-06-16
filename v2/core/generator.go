package core

import (
	"context"
	"strings"
	"sync"

	"github.com/chainreactors/gogo/v2/engine"
	. "github.com/chainreactors/gogo/v2/pkg"
	. "github.com/chainreactors/logs"
	"github.com/chainreactors/parsers"
	"github.com/chainreactors/utils"
)

func NewIpGenerator(config Config) *IpGenerator {
	var alivemap sync.Map
	gen := IpGenerator{
		ctx:       config.Context(),
		alivedMap: &alivemap,
		ipProbe:   config.IpProbeList,
	}
	return &gen
}

type IpGenerator struct {
	ctx       context.Context
	count     int
	ch        chan string
	alivedMap *sync.Map
	ipProbe   []uint
}

func (gen *IpGenerator) defaultIpGenerator(cidr *utils.CIDR) {
	for ip := range cidr.Range() {
		var s string
		if ip.Ver == 6 {
			s = "[" + ip.String() + "]"
		} else {
			s = ip.String()
		}
		select {
		case gen.ch <- s:
		case <-gen.ctx.Done():
			return
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
				select {
				case gen.ch <- c.Next().String():
				case <-gen.ctx.Done():
					return
				}
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
			ip := c[i]
			for _, p := range gen.ipProbe {
				count++
				tip := ip.Copy()
				tip.IP[3] = byte(p)
				if isnotAlive(b, gen.alivedMap) {
					select {
					case gen.ch <- tip.String():
					case <-gen.ctx.Done():
						return
					}
				}
			}
		}
	}
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
		ctx:         config.Context(),
		ipGenerator: NewIpGenerator(config),
		spray:       config.PortSpray,
		hostsMap:    config.HostsMap,
		syncFile:    config.SyncFile,
	}
	return &gen
}

type TargetGenerator struct {
	ctx         context.Context
	count       int
	spray       bool
	ch          chan targetConfig
	hostsMap    map[string][]string
	ipGenerator *IpGenerator
	syncFile    func()
}

func (gen *TargetGenerator) syncOutputFile() {
	if gen.syncFile != nil {
		gen.syncFile()
	}
}

func (gen *TargetGenerator) genFromDefault(cidrs utils.CIDRs, portlist []string) {
	for _, cidr := range cidrs {
		tmpalived := Opt.AliveSum
		ch := gen.ipGenerator.generatorDispatch(cidr, Default)
		for ip := range ch {
			for _, port := range portlist {
				select {
				case gen.ch <- targetConfig{ip: ip, port: port, hosts: gen.hostsMap[ip]}:
				case <-gen.ctx.Done():
					return
				}
				if engine.RunSum%65535 == 65534 {
					Log.Importantf("Current processing %s:%s, number: %d", ip, port, engine.RunSum)
				}
			}
		}
		if cidr.Count() > 1 {
			Log.Importantf("Scanned %s with %d ports, found %d ports", cidr.String(), len(portlist), Opt.AliveSum-tmpalived)
		}
		gen.syncOutputFile()
	}
}

func (gen *TargetGenerator) genFromSpray(cidrs utils.CIDRs, portlist []string) {
	var tmpPorts []string
	for _, port := range portlist {
		lastalive := Opt.AliveSum

		for _, cidr := range cidrs {
			ch := gen.ipGenerator.generatorDispatch(cidr, Default)
			for ip := range ch {
				select {
				case gen.ch <- targetConfig{ip: ip, port: port, hosts: gen.hostsMap[ip]}:
				case <-gen.ctx.Done():
					return
				}
			}
			gen.syncOutputFile()
		}

		tmpPorts = append(tmpPorts, port)
		if Opt.AliveSum-lastalive > 0 {
			if len(tmpPorts) > 5 {
				Log.Importantf("Processed Port: %s - %s, found %d ports", tmpPorts[0], tmpPorts[len(tmpPorts)-1], Opt.AliveSum-lastalive)
			} else {
				Log.Importantf("Processed Port: %s, found %d ports", strings.Join(tmpPorts, ","), Opt.AliveSum-lastalive)
			}
			tmpPorts = []string{}
		}
	}
}

func (gen *TargetGenerator) genFromResult(results parsers.GOGOResults) {
	for _, result := range results {
		select {
		case gen.ch <- targetConfig{ip: result.Ip, port: result.Port, fingers: result.Frameworks}:
		case <-gen.ctx.Done():
			return
		}
	}
}

func (gen *TargetGenerator) generatorDispatch(targets interface{}, portlist []string) chan targetConfig {
	gen.ch = make(chan targetConfig)
	go func() {
		switch v := targets.(type) {
		case parsers.GOGOResults:
			gen.genFromResult(v)
		case utils.CIDRs:
			if gen.spray { // 端口喷洒
				gen.genFromSpray(v, portlist)
			} else { // 默认模式 批量处理
				gen.genFromDefault(v, portlist)
			}
		}
		close(gen.ch)
	}()

	return gen.ch
}

func (gen *TargetGenerator) smartGenerator(cidr *utils.CIDR, portlist []string, mod string) chan targetConfig {
	gen.ch = make(chan targetConfig)

	go func() {
		defer close(gen.ch)
		ch := gen.ipGenerator.generatorDispatch(cidr, mod)
		for ip := range ch {
			for _, port := range portlist {
				select {
				case gen.ch <- targetConfig{ip: ip, port: port}:
				case <-gen.ctx.Done():
					return
				}
			}
		}
	}()
	return gen.ch
}
