package core

import (
	"fmt"
	"github.com/chainreactors/fingers/common"
	"github.com/chainreactors/gogo/v2/engine"
	"net"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	. "github.com/chainreactors/gogo/v2/pkg"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/utils"
	"github.com/panjf2000/ants/v2"
)

type targetConfig struct {
	ip      string
	port    string
	hosts   []string
	fingers common.Frameworks
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

	//if plugin.RunOpt.SuffixStr != "" && !strings.HasPrefix(plugin.RunOpt.SuffixStr, "/") {
	//	result.Uri = "/" + plugin.RunOpt.SuffixStr
	//}
	return result
}

// 直接扫描
func DefaultMod(targets interface{}, config Config) {
	// 输出预估时间
	logs.Log.Importantf("Default Scan is expected to take %d seconds", guessTime(targets, len(config.PortList), config.Threads))
	var wgs sync.WaitGroup
	targetGen := NewTargetGenerator(config)
	targetCh := targetGen.generatorDispatch(targets, config.PortList)
	scanPool, _ := ants.NewPoolWithFunc(config.Threads, func(i interface{}) {
		defer wgs.Done()
		tc := i.(targetConfig)
		result := tc.NewResult()
		engine.Dispatch(result)
		if result.Open {
			atomic.AddInt32(&Opt.AliveSum, 1)

			if !result.Filtered {
				// 如果以及被过滤, 不需要进行进一步过滤
				result.Filter(config.OutputFilters)
			}

			if result.Filtered {
				logs.Log.Debug("[filtered] " + output(result, config.Outputf))
			} else {
				logs.Log.Console(output(result, config.Outputf))
			}
			// 文件输出
			if config.File != nil {
				if !config.File.IsInitialized() {
					logs.Log.Important("init file: " + config.File.GetFilename())
				}
				config.File.WriteString(output(result, config.FileOutputf))
			}
		} else if result.Error != "" {
			logs.Log.Debugf("%s stat: %s, errmsg: %s", result.GetTarget(), PortStat[result.ErrStat], result.Error)
		}
	}, ants.WithPanicHandler(func(err interface{}) {
		if Opt.PluginDebug == true {
			debug.PrintStack()
		}
	}))
	defer scanPool.Release()

	for t := range targetCh {
		wgs.Add(1)
		_ = scanPool.Invoke(t)
	}

	wgs.Wait()
}

func SmartMod(target *utils.CIDR, config Config) {
	// 初始化mask
	var mask int
	switch config.Mod {
	case SUPERSMART, SUPERSMARTB:
		// sc, ss
		if target.Mask > 16 {
			logs.Log.Error(target.String() + " is less than B class, skipped")
		}
		mask = 16
		if config.PortProbe == Default {
			config.PortProbeList = DefaultSuperSmartPortProbe
		}
	default:
		// s
		if target.Mask > 24 {
			logs.Log.Error(target.String() + " is less than C class, skipped")
			return
		}
		mask = 24
		if config.PortProbe == Default {
			config.PortProbeList = DefaultSmartPortProbe
		}
	}
	spended := guessSmartTime(target, config)
	logs.Log.Importantf("Spraying %s with %s, Estimated to take %d seconds", target, config.Mod, spended)
	var wg sync.WaitGroup

	//var ipChannel chan string
	targetGen := NewTargetGenerator(config)
	temp := targetGen.ipGenerator.alivedMap

	// 输出启发式扫描探针
	probeconfig := fmt.Sprintf("Smart port probes: %s ", strings.Join(config.PortProbeList, ","))
	if config.IsBSmart() {
		probeconfig += ", Smart IP probes: " + fmt.Sprintf("%v", config.IpProbeList)
	}
	logs.Log.Important(probeconfig)

	tcChannel := targetGen.smartGenerator(target, config.PortProbeList, config.Mod)

	scanPool, _ := ants.NewPoolWithFunc(config.Threads, func(i interface{}) {
		tc := i.(targetConfig)
		result := NewResult(tc.ip, tc.port)
		result.SmartProbe = true
		engine.Dispatch(result)

		if result.Open {
			logs.Log.Debug("cidr scan , " + result.String())
			cidrAlived(result.Ip, temp, mask)
		} else if result.Error != "" {
			logs.Log.Debugf("%s stat: %s, errmsg: %s", result.GetTarget(), PortStat[result.ErrStat], result.Error)
		}
		wg.Done()
	})
	defer scanPool.Release()
	for t := range tcChannel {
		wg.Add(1)
		_ = scanPool.Invoke(t)
	}
	wg.Wait()

	var iplist utils.CIDRs
	temp.Range(func(ip, _ interface{}) bool {
		iplist = append(iplist, utils.NewCIDR(ip.(string), mask))
		return true
	})

	// 网段排序
	if len(iplist) > 0 {
		sort.Sort(iplist)
	} else {
		return
	}

	logs.Log.Importantf("Smart scan: %s finished, found %d alive cidrs", target, len(iplist))
	if config.IsBSmart() {
		WriteSmartResult(config.SmartBFile, target.String(), iplist.Strings())
	}
	if config.IsCSmart() {
		WriteSmartResult(config.SmartCFile, target.String(), iplist.Strings())
	}

	if Opt.NoScan || config.Mod == SUPERSMARTC {
		// -no 被设置的时候停止后续扫描
		return
	}
	createDeclineScan(iplist, config)
}

func AliveMod(targets interface{}, config Config) {
	if !Win && !Root {
		// linux的普通用户无权限使用icmp或arp扫描
		logs.Log.Warn("must be *unix's root, skipped ping/arp spray")
		DefaultMod(targets, config)
		return
	}

	var wgs sync.WaitGroup
	logs.Log.Importantf("Alived spray task is expected to take %d seconds",
		guessTime(targets, len(config.AliveSprayMod), config.Threads))
	targetGen := NewTargetGenerator(config)
	alivedmap := targetGen.ipGenerator.alivedMap
	targetCh := targetGen.generatorDispatch(targets, config.AliveSprayMod)
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
		iplist = append(iplist, ip.(string))
		return true
	})

	if len(iplist) == 0 {
		logs.Log.Important("not found any alived ip")
		return
	}
	logs.Log.Importantf("found %d alived ips", len(iplist))
	if config.AliveFile != nil {
		WriteSmartResult(config.AliveFile, "alive", iplist)
	}
	DefaultMod(utils.ParseIPs(iplist).CIDRs(), config)
}

func aliveScan(tc targetConfig, temp *sync.Map) {
	result := NewResult(tc.ip, tc.port)
	result.SmartProbe = true
	engine.Dispatch(result)

	if result.Open {
		logs.Log.Debug("alive scan, " + result.String())
		temp.Store(result.Ip, true)
		atomic.AddInt32(&Opt.AliveSum, 1)
	}
}

func cidrAlived(ip string, temp *sync.Map, mask int) {
	i := net.ParseIP(ip)
	alivecidr := i.Mask(net.CIDRMask(mask, 32)).String()
	_, ok := temp.Load(alivecidr)
	if !ok {
		temp.Store(alivecidr, 1)
		logs.Log.Importantf("Found %s/%d", ip, mask)
		atomic.AddInt32(&Opt.AliveSum, 1)
	}
}

func createDefaultScan(config Config) {
	if config.Results != nil {
		DefaultMod(config.Results, config)
	} else {
		if config.HasAlivedScan() {
			AliveMod(config.CIDRs, config)
		} else {
			DefaultMod(config.CIDRs, config)
		}
	}
}

func createDeclineScan(cidrs utils.CIDRs, config Config) {
	// 启发式扫描逐步降级,从喷洒B段到喷洒C段到默认扫描
	if config.Mod == SUPERSMART {
		// 如果port数量为1, 直接扫描的耗时小于启发式
		// 如果port数量为2, 直接扫描的耗时约等于启发式扫描
		// 因此, 如果post数量小于等于2, 则直接使用defaultScan
		config.Mod = SMART
		if len(config.PortList) <= 3 {
			logs.Log.Important("ports less than 3, skipped smart scan.")
			if config.HasAlivedScan() {
				AliveMod(config.CIDRs, config)
			} else {
				DefaultMod(config.CIDRs, config)
			}
		} else {
			spended := guessSmartTime(cidrs[0], config)
			logs.Log.Importantf("Every smartscan subtask is expected to take %d seconds, total found %d B Class CIDRs about %d s", spended, len(cidrs), spended*len(cidrs))
			for _, ip := range cidrs {
				tmpalive := Opt.AliveSum
				SmartMod(ip, config)
				logs.Log.Importantf("Found %d assets from CIDR %s", Opt.AliveSum-tmpalive, ip)
				syncFile()
			}
		}
	} else if config.Mod == SUPERSMARTB {
		config.Mod = SUPERSMARTC
		spended := guessSmartTime(cidrs[0], config)
		logs.Log.Importantf("Every smartscan subtask is expected to take %d seconds, total found %d B Class CIDRs about %d s", spended, len(cidrs), spended*len(cidrs))

		for _, ip := range cidrs {
			SmartMod(ip, config)
		}
	} else {
		config.Mod = Default
		if config.HasAlivedScan() {
			AliveMod(cidrs, config)
		} else {
			DefaultMod(cidrs, config)
		}
	}
}
