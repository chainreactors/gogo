package core

import (
	"fmt"
	. "getitle/src/pkg"
	"getitle/src/scan"
	"github.com/panjf2000/ants/v2"
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
		result.HttpHost = tc.hosts
	}
	if tc.fingers != nil {
		result.Frameworks = tc.fingers
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
	Log.Logging(fmt.Sprintf("[*] Scan task time is about %d seconds", guessTime(targets, len(config.Portlist), config.Threads)))
	var wgs sync.WaitGroup
	targetGen := NewTargetGenerator(config)
	targetCh := targetGen.generator(targets, config.Portlist)
	//targetChannel := generator(targets, config)
	scanPool, _ := ants.NewPoolWithFunc(config.Threads, func(i interface{}) {
		defaultScan(i.(targetConfig))
		wgs.Done()
	})
	defer scanPool.Release()

	for t := range targetCh {
		wgs.Add(1)
		_ = scanPool.Invoke(t)
	}

	wgs.Wait()
}

func defaultScan(tc targetConfig) {
	result := tc.NewResult()
	scan.Dispatch(result)

	if result.Open {
		Opt.AliveSum++
		// 格式化title编码, 防止输出二进制数据
		result.Title = AsciiEncode(result.Title)
		Log.Default(output(result, Opt.Output))

		if Opt.File != nil {
			Opt.dataCh <- output(result, Opt.FileOutput)
			if result.Extracts.Extractors != nil {
				Opt.extractCh <- result.Extracts.ToResult()
			}
		}
	} else if Opt.Debug && (result.ErrStat != 0 || result.Error != "") {
		fmt.Printf("[debug] %s stat: %s, errmsg: %s\n", result.GetTarget(), portstat[result.ErrStat], result.Error)
	}
}

func SmartMod(target string, config Config) {
	// 输出预估时间
	spended := guessSmarttime(target, config)
	Log.Logging(fmt.Sprintf("[*] Spraying B class IP: %s, Estimated to take %d seconds", target, spended))

	// 初始化ip目标
	Log.Logging(fmt.Sprintf("[*] SmartScan %s, Mod: %s", target, config.Mod))
	// 初始化mask
	var mask int
	switch config.Mod {
	case "ss", "sc":
		mask = 16
	case "s", "sb":
		mask = 24
	}

	var wg sync.WaitGroup

	//var ipChannel chan string
	targetGen := NewTargetGenerator(config)
	temp := targetGen.ipGenerator.alivedMap

	// 输出启发式扫描探针
	probeconfig := fmt.Sprintf("[*] Smart probe ports: %s , ", strings.Join(config.SmartPortList, ","))
	if config.IsASmart() {
		probeconfig += "Smart IP probe: " + config.IpProbe
	}
	Log.Logging(probeconfig)

	tcChannel := targetGen.smartGenerator(target, config.SmartPortList, config.Mod)

	scanPool, _ := ants.NewPoolWithFunc(config.Threads, func(i interface{}) {
		tc := i.(targetConfig)
		smartScan(tc, temp, mask, config.Mod)
		wg.Done()
	})

	defer scanPool.Release()
	for t := range tcChannel {
		wg.Add(1)
		_ = scanPool.Invoke(t)
	}
	wg.Wait()

	var iplist []string
	temp.Range(func(ip, _ interface{}) bool {
		iplist = append(iplist, fmt.Sprintf("%s/%d", ip.(string), mask))
		return true
	})

	// 网段排序
	if len(iplist) > 0 {
		sort_cidr(iplist)
	} else {
		return
	}

	if Opt.SmartFile != nil {
		writeSmartResult(iplist)
	}

	if Opt.Noscan {
		// -no 被设置的时候停止后续扫描
		return
	}

	// 启发式扫描逐步降级,从喷洒B段到喷洒C段到默认扫描
	if config.Mod == "ss" {
		config.Mod = "s"
		declineScan(iplist, config)
	} else if config.Mod == "sc" {
		config.Mod = "sb"
		declineScan(iplist, config)
	} else if config.Mod == "s" {
		if config.HasAlivedScan() {
			AliveMod(iplist, config)
		} else {
			DefaultMod(iplist, config)
		}
	}
}

func cidr_alived(ip string, temp *sync.Map, mask int, mod string) {
	alivecidr := ip2superip(ip, mask)
	_, ok := temp.Load(alivecidr)
	if !ok {
		temp.Store(alivecidr, 1)
		cidr := fmt.Sprintf("%s/%d", ip, mask)
		Log.Logging("[+] Found " + cidr)
		Opt.AliveSum++
		//if Opt.File != nil {
		//	// 只有-no 或 -m sc下,才会将网段信息输出到文件.
		//	// 模式为sc时,b段将不会输出到文件,只输出c段
		//	Opt.dataCh <- "\"" + cidr + "\""
		//}
	}
}

func smartScan(tc targetConfig, temp *sync.Map, mask int, mod string) {
	result := NewResult(tc.ip, tc.port)
	result.SmartProbe = true
	scan.Dispatch(result)

	if result.Open {
		cidr_alived(result.Ip, temp, mask, mod)
	} else if Opt.Debug {
		fmt.Printf("[debug] tcp stat: %s, errmsg: %s\n", portstat[result.ErrStat], result.Error)
	}
}

func declineScan(iplist []string, config Config) {
	//config.IpProbeList = []uint{1} // ipp 只在ss与sc模式中生效,为了防止时间计算错误,reset ipp 数值
	if config.Mod != "sb" && len(config.Portlist) < 3 {
		// 如果port数量为1, 直接扫描的耗时小于启发式
		// 如果port数量为2, 直接扫描的耗时约等于启发式扫描
		// 因此, 如果post数量小于2, 则直接使用defaultScan
		Log.Logging("[*] port count less than 3, skipped smart scan.")

		if config.HasAlivedScan() {
			AliveMod(iplist, config)
		} else {
			DefaultMod(iplist, config)
		}
	} else {
		spended := guessSmarttime(iplist[0], config)
		Log.Logging(fmt.Sprintf("[*] Every Sub smartscan task time is about %d seconds, total found %d B Class CIDRs about %d s", spended, len(iplist), spended*len(iplist)))

		for _, ip := range iplist {
			tmpalive := Opt.AliveSum
			SmartMod(ip, config)
			Log.Logging(fmt.Sprintf("[*] Found %d assets from CIDR %s", Opt.AliveSum-tmpalive, ip))
			Opt.File.Sync()
		}
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
	Log.Logging(fmt.Sprintf("[*] Alived spray task time is about %d seconds",
		guessTime(targets, len(config.AliveSprayMod), config.Threads)))
	targetGen := NewTargetGenerator(config)
	alivedmap := targetGen.ipGenerator.alivedMap
	targetCh := targetGen.generator(targets, config.AliveSprayMod)
	//targetChannel := generator(targets, config)
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

	var iplist []string
	alivedmap.Range(func(ip, _ interface{}) bool {
		iplist = append(iplist, ip.(string)+"/32")
		return true
	})

	if len(iplist) == 0 {
		Log.Logging(fmt.Sprintf("[*] not found any alived ip"))
		return
	}
	Log.Logging(fmt.Sprintf("[*] found %d alived ips", len(iplist)))
	if Opt.AliveFile != nil {
		writePingResult(iplist)
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
