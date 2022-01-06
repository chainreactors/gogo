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

//直接扫描
func StraightMod(targets interface{}, config Config) {
	// 输出预估时间
	progressLogln(fmt.Sprintf("[*] Scan task time is about %d seconds", guessTime(config)))
	var wgs sync.WaitGroup
	targetChannel := generator(targets, config)
	scanPool, _ := ants.NewPoolWithFunc(config.Threads, func(i interface{}) {
		defaultScan(i.(targetConfig))
		wgs.Done()
	})
	defer scanPool.Release()

	for t := range targetChannel {
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
		if !Opt.Clean {
			fmt.Print(output(result, Opt.Output))
		}
		if Opt.fileHandle != nil {
			Opt.DataCh <- output(result, Opt.FileOutput)
		}
	}
}

func SmartMod(target string, config Config) {
	// 输出预估时间
	spended := guessSmarttime(target, config)
	progressLogln(fmt.Sprintf("[*] Spraying B class IP: %s, Estimated to take %d seconds", target, spended))

	// 初始化ip目标
	progressLogln(fmt.Sprintf("[*] SmartScan %s, Mod: %s", target, config.Mod))
	// 初始化mask
	var mask int
	switch config.Mod {
	case "ss", "sc":
		mask = 16
	case "s", "sb":
		mask = 24
	}

	var wg sync.WaitGroup
	var temp sync.Map

	//go safeMap(&temp, aliveC)
	//var ipChannel chan string
	ipChannel := ipGenerator(target, config.Mod, config.IpProbeList, &temp)

	var tcChannel chan targetConfig

	// 输出启发式扫描探针
	probeconfig := fmt.Sprintf("[*] Smart probe ports: %s , ", strings.Join(config.SmartPortList, ","))
	if config.Mod == "ss" {
		probeconfig += "Smart IP probe: " + config.IpProbe
	}
	progressLogln(probeconfig)

	tcChannel = tcGenerator(ipChannel, config.SmartPortList)
	scanPool, _ := ants.NewPoolWithFunc(config.Threads, func(i interface{}) {
		tc := i.(targetConfig)
		smartScan(tc, &temp, mask, config.Mod)
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

	if Opt.smartFileHandle != nil {
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
		StraightMod(iplist, config)
	}
}

func alived(ip string, temp *sync.Map, mask int, mod string) {
	alivecidr := ip2superip(ip, mask)
	_, ok := temp.LoadOrStore(alivecidr, 1)
	if ok {
		cidr := fmt.Sprintf("%s/%d", ip, mask)
		ConsoleLog("[*] Found " + cidr)
		Opt.AliveSum++
		if Opt.fileHandle != nil && mod != "sc" && (Opt.Noscan || mod == "sb") {
			// 只有-no 或 -m sc下,才会将网段信息输出到文件.
			// 模式为sc时,b段将不会输出到文件,只输出c段
			Opt.DataCh <- cidr
		}
	}
}

func smartScan(tc targetConfig, temp *sync.Map, mask int, mod string) {
	result := NewResult(tc.ip, tc.port)
	scan.Dispatch(result)

	if result.Open {
		alived(result.Ip, temp, mask, mod)
	}
}

func declineScan(iplist []string, config Config) {
	//config.IpProbeList = []uint{1} // ipp 只在ss与sc模式中生效,为了防止时间计算错误,reset ipp 数值
	if len(iplist) > 0 && len(config.Portlist) >= 3 {
		spended := guessSmarttime(iplist[0], config)
		progressLogln(fmt.Sprintf("[*] Every Sub smartscan task time is about %d seconds, total found %d B Class CIDRs about %d s", spended, len(iplist), spended*len(iplist)))
	}
	for _, ip := range iplist {
		tmpalive := Opt.AliveSum
		if len(config.Portlist) < 3 {
			StraightMod(ip, config)
		} else {
			SmartMod(ip, config)
		}
		progressLogln(fmt.Sprintf("[*] Found %d alive assets from CIDR %s", Opt.AliveSum-tmpalive, ip))
		fileFlush()
	}
}
