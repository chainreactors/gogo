package core

import (
	"fmt"
	"getitle/v1/internal/scan"
	. "getitle/v1/pkg"
	"github.com/chainreactors/ipcs"
	. "github.com/chainreactors/logs"
	"github.com/panjf2000/ants/v2"
	"net"
	"sort"
	"strings"
	"sync"
)

type targetConfig struct {
	ip      string
	port    string
	hosts   []string
	fingers Frameworks
}

func (tc *targetConfig) NewResult() *Result {
	result := NewResult(tc.ip, tc.port)
	if tc.hosts != nil {
		if len(tc.hosts) == 1 {
			result.CurrentHost = tc.hosts[0]
		}
		result.HttpHosts = tc.hosts
	}
	if tc.fingers != nil {
		result.Frameworks = tc.fingers
	}

	if scan.RunOpt.SuffixStr != "" && !strings.HasPrefix(scan.RunOpt.SuffixStr, "/") {
		result.Uri = "/" + scan.RunOpt.SuffixStr
	}
	return result
}

// return open: 0, closed: 1, filtered: 2, noroute: 3, denied: 4, down: 5, error_host: 6, unkown: -1

var portstat = map[int]string{
	//0:  "open",
	1:  "closed",
	2:  "filtered|closed",
	3:  "noroute",
	4:  "denied",
	5:  "down",
	6:  "error_host",
	-1: "unknown",
}

//直接扫描
func DefaultMod(targets interface{}, config Config) {
	// 输出预估时间
	Log.Importantf("Default Scan time is about %d seconds", guessTime(targets, len(config.Portlist), config.Threads))
	var wgs sync.WaitGroup
	targetGen := NewTargetGenerator(config)
	targetCh := targetGen.generatorDispatch(targets, config.Portlist)
	//targetChannel := generatorDispatch(targets, config)
	scanPool, _ := ants.NewPoolWithFunc(config.Threads, func(i interface{}) {
		tc := i.(targetConfig)
		result := tc.NewResult()
		scan.Dispatch(result)
		if result.Open {
			Opt.AliveSum++
			// 格式化title编码, 防止输出二进制数据
			result.Title = AsciiEncode(result.Title)
			Log.Console(output(result, config.Outputf))

			if config.File != nil {
				if !config.File.Initialized {
					Log.Important("init file: " + config.File.Filename)
				}
				config.File.SafeWrite(output(result, config.FileOutputf))
				if result.Extracts.Extractors != nil {
					config.ExtractFile.SafeWrite(result.Extracts.ToResult())
				}
			}
		} else if result.Error != "" {
			Log.Debugf("%s tcp stat: %s, errmsg: %s", result.GetTarget(), portstat[result.ErrStat], result.Error)
		}
		wgs.Done()
	})
	defer scanPool.Release()

	for t := range targetCh {
		wgs.Add(1)
		_ = scanPool.Invoke(t)
	}

	wgs.Wait()
}

func SmartMod(target *ipcs.CIDR, config Config) {
	// 输出预估时间
	spended := guessSmartTime(target, config)
	Log.Importantf("Spraying %s with %s, Estimated to take %d seconds", target, config.Mod, spended)

	// 初始化ip目标
	//Log.Importantf("SmartScan %s, Mod: %s", target, config.Mod)
	// 初始化mask
	var mask int
	switch config.Mod {
	case SUPERSMART, SUPERSMARTB:
		mask = 16
	case SMART, SUPERSMARTC:
		mask = 24
	}

	var wg sync.WaitGroup

	//var ipChannel chan string
	targetGen := NewTargetGenerator(config)
	temp := targetGen.ipGenerator.alivedMap

	// 输出启发式扫描探针
	probeconfig := fmt.Sprintf("Smart probe ports: %s , ", strings.Join(config.SmartPortList, ","))
	if config.IsASmart() {
		probeconfig += "Smart IP probe: " + config.IpProbe
	}
	Log.Important(probeconfig)

	tcChannel := targetGen.smartGenerator(target, config.SmartPortList, config.Mod)

	scanPool, _ := ants.NewPoolWithFunc(config.Threads, func(i interface{}) {
		tc := i.(targetConfig)
		result := NewResult(tc.ip, tc.port)
		result.SmartProbe = true
		scan.Dispatch(result)

		if result.Open {
			cidrAlived(result.Ip, temp, mask, config.Mod)
		} else if result.Error != "" {
			Log.Debugf("tcp stat: %s, errmsg: %s", portstat[result.ErrStat], result.Error)
		}
		wg.Done()
	})

	defer scanPool.Release()
	for t := range tcChannel {
		wg.Add(1)
		_ = scanPool.Invoke(t)
	}
	wg.Wait()

	var iplist ipcs.CIDRs
	temp.Range(func(ip, _ interface{}) bool {
		iplist = append(iplist, ipcs.NewCIDR(ip.(string), mask))
		return true
	})

	// 网段排序
	if len(iplist) > 0 {
		sort.Sort(iplist)
	} else {
		return
	}

	if config.SmartFile != nil && config.Mod != SUPERSMARTC {
		WriteSmartResult(config.SmartFile, iplist.Strings())
	}
	if config.File != nil && config.Mod == SUPERSMARTC {
		config.File.SafeWrite(strings.Join(iplist.Strings(), "\n") + "\n")
	}

	if Opt.Noscan || config.Mod == SUPERSMARTC {
		// -no 被设置的时候停止后续扫描
		return
	}

	// 启发式扫描逐步降级,从喷洒B段到喷洒C段到默认扫描
	if config.Mod == SUPERSMART {
		config.Mod = SMART
	} else if config.Mod == SUPERSMARTB {
		config.Mod = SUPERSMARTC
	} else {
		config.Mod = "default"
	}
	declineScan(iplist, config)
}

func cidrAlived(ip string, temp *sync.Map, mask int, mod string) {
	i, _ := ipcs.ParseIP(ip)
	alivecidr := i.Mask(mask).String()
	_, ok := temp.Load(alivecidr)
	if !ok {
		temp.Store(alivecidr, 1)
		cidr := fmt.Sprintf("%s/%d", ip, mask)
		Log.Important("Found " + cidr)
		Opt.AliveSum++
		//if Opt.File != nil && (Opt.Noscan || mod == SUPERSMARTB){
		//	// 只有-no 或 -m sc下,才会将网段信息输出到文件.
		//	// 模式为sc时,b段将不会输出到文件,只输出c段
		//	Opt.dataCh <- "\"" + cidr + "\""
		//}
	}
}

func declineScan(cidrs ipcs.CIDRs, config Config) {
	//config.IpProbeList = []uint{1} // ipp 只在ss与sc模式中生效,为了防止时间计算错误,reset ipp 数值
	if config.Mod == SMART {
		// 如果port数量为1, 直接扫描的耗时小于启发式
		// 如果port数量为2, 直接扫描的耗时约等于启发式扫描
		// 因此, 如果post数量小于2, 则直接使用defaultScan
		if len(config.Portlist) < 3 {
			Log.Important("port count less than 3, skipped smart scan.")

			if config.HasAlivedScan() {
				AliveMod(cidrs, config)
			} else {
				DefaultMod(cidrs, config)
			}
		} else {
			spended := guessSmartTime(cidrs[0], config)
			Log.Importantf("Every Sub smartscan task time is about %d seconds, total found %d B Class CIDRs about %d s", spended, len(cidrs), spended*len(cidrs))
			for _, ip := range cidrs {
				tmpalive := Opt.AliveSum
				SmartMod(ip, config)
				Log.Importantf("Found %d assets from CIDR %s", Opt.AliveSum-tmpalive, ip)
				syncFile()
			}
		}

	} else if config.Mod == SUPERSMARTC {
		spended := guessSmartTime(cidrs[0], config)
		Log.Importantf("Every Sub smartscan task time is about %d seconds, total found %d B Class CIDRs about %d s", spended, len(cidrs), spended*len(cidrs))

		for _, ip := range cidrs {
			SmartMod(ip, config)
		}
	} else {
		DefaultMod(cidrs, config)
	}
}

func AliveMod(targets interface{}, config Config) {
	if !Win && !Root {
		// linux的普通用户无权限使用icmp或arp扫描
		Log.Warn("must be *unix's root, skipped ping/arp spray")
		DefaultMod(targets, config)
		return
	}

	var wgs sync.WaitGroup
	Log.Importantf("Alived spray task time is about %d seconds",
		guessTime(targets, len(config.AliveSprayMod), config.Threads))
	targetGen := NewTargetGenerator(config)
	alivedmap := targetGen.ipGenerator.alivedMap
	targetCh := targetGen.generatorDispatch(targets, config.AliveSprayMod)
	//targetChannel := generatorDispatch(targets, config)
	scanPool, _ := ants.NewPoolWithFunc(config.Threads, func(i interface{}) {
		aliveScan(i.(targetConfig), alivedmap)
		wgs.Done()
	})
	defer scanPool.Release()

	for t := range targetCh {
		wgs.Add(1)
		_ = scanPool.Invoke(t)
	}

	wgs.Wait()

	var iplist ipcs.CIDRs
	alivedmap.Range(func(ip, _ interface{}) bool {
		iplist = append(iplist, &ipcs.CIDR{&ipcs.IP{IP: net.ParseIP(ip.(string)).To4()}, 32})
		return true
	})

	if len(iplist) == 0 {
		Log.Important("not found any alived ip")
		return
	}
	Log.Importantf("found %d alived ips", len(iplist))
	if config.AliveFile != nil {
		WriteAlivedResult(config.AliveFile, iplist.Strings())
	}
	DefaultMod(iplist, config)
}

func aliveScan(tc targetConfig, temp *sync.Map) {
	result := NewResult(tc.ip, tc.port)
	scan.Dispatch(result)

	if result.Open {
		temp.Store(result.Ip, true)
		Opt.AliveSum++
	}
}
