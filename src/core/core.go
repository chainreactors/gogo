package core

import (
	"fmt"
	"getitle/src/scan"
	. "getitle/src/utils"
	"github.com/panjf2000/ants/v2"
	"strings"
	"sync"
)

type targetConfig struct {
	ip     string
	port   string
	finger Frameworks
}

// return open: 0, closed: 1, filtered: 2, noroute: 3, denied: 4, down: 5, error_host: 6, unkown: -1

var portstat = map[int]string{
	0:  "open",
	1:  "closed",
	2:  "filtered|closed",
	3:  "noroute",
	4:  "denied",
	5:  "down",
	6:  "error_host",
	-1: "unknow",
}

//直接扫描
func DefaultMod(targets interface{}, config Config) {
	// 输出预估时间
	Log.Logging(fmt.Sprintf("[*] Scan task time is about %d seconds", guessTime(targets, config.Portlist, config.Threads)))
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
	result := NewResult(tc.ip, tc.port)
	scan.Dispatch(result)

	if result.Open {
		Opt.AliveSum++
		Log.Default(output(result, Opt.Output))

		if Opt.file != nil {
			Opt.DataCh <- output(result, Opt.FileOutput)
			if result.Extracts.Extracts != nil {
				Opt.ExtractCh <- result.Extracts.ToResult()
			}
		}
	} else if Opt.Debug {
		fmt.Printf("[debug] tcp stat: %s, errmsg: %s\n", portstat[result.ErrStat], result.Error)
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
	temp := targetGen.ip_generator.alivedMap

	// 输出启发式扫描探针
	probeconfig := fmt.Sprintf("[*] Smart probe ports: %s , ", strings.Join(config.SmartPortList, ","))
	if config.Mod == "ss" {
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

	if Opt.Noscan {
		// -no 被设置的时候停止后续扫描
		return
	}

	var iplist []string
	temp.Range(func(ip, _ interface{}) bool {
		iplist = append(iplist, fmt.Sprintf("%s/%d", ip.(string), mask))
		return true
	})

	if iplist == nil {
		return
	} else {
		sort_cidr(iplist)
	}

	if Opt.smartFile != nil {
		writeSmartResult(iplist)
	}

	// 启发式扫描逐步降级,从喷洒B段到喷洒C段到默认扫描
	if config.Mod == "ss" {
		config.Mod = "s"
		declineScan(iplist, config)
	} else if config.Mod == "sc" {
		config.Mod = "sb"
		declineScan(iplist, config)
	} else if config.Mod == "s" {
		if config.Ping {
			PingMod(iplist, config)
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
		Log.Important("[*] Found " + cidr)
		Opt.AliveSum++
		if Opt.file != nil && mod != "sc" && (Opt.Noscan || mod == "sb") {
			// 只有-no 或 -m sc下,才会将网段信息输出到文件.
			// 模式为sc时,b段将不会输出到文件,只输出c段
			Opt.DataCh <- cidr + "\n"
		}
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

	if len(config.Portlist) < 3 {
		if config.Ping {
			PingMod(iplist, config)
		} else {
			DefaultMod(iplist, config)
		}
	} else {
		spended := guessSmarttime(iplist[0], config)
		Log.Logging(fmt.Sprintf("[*] Every Sub smartscan task time is about %d seconds, total found %d B Class CIDRs about %d s", spended, len(iplist), spended*len(iplist)))

		for _, ip := range iplist {
			tmpalive := Opt.AliveSum
			SmartMod(ip, config)
			Log.Logging(fmt.Sprintf("[*] Found %d alive assets from CIDR %s", Opt.AliveSum-tmpalive, ip))
			Opt.file.Sync()
		}
	}
}

func PingMod(targets interface{}, config Config) {
	var wgs sync.WaitGroup
	Log.Logging(fmt.Sprintf("[*] Ping spray task time is about %d seconds", guessTime(targets, config.Portlist, guessTime(targets, []string{"icmp"}, config.Threads))))
	targetGen := NewTargetGenerator(config)
	alivedmap := targetGen.ip_generator.alivedMap
	targetCh := targetGen.generator(targets, []string{"icmp"})
	//targetChannel := generator(targets, config)
	scanPool, _ := ants.NewPoolWithFunc(config.Threads, func(i interface{}) {
		pingScan(i.(targetConfig), alivedmap)
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
	if Opt.pingFile != nil {
		writePingResult(iplist)
	}
	DefaultMod(iplist, config)
}

func pingScan(tc targetConfig, temp *sync.Map) {
	result := NewResult(tc.ip, tc.port)
	scan.Dispatch(result)

	if result.Open {
		temp.Store(result.Ip, true)
		Opt.AliveSum++
	}
}
