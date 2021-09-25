package core

import (
	"fmt"
	"getitle/src/scan"
	"getitle/src/utils"
	"github.com/panjf2000/ants/v2"
	"net"
	"sort"
	"strings"
	"sync"
)

var Alivesum int

type targetConfig struct {
	ip     string
	port   string
	finger utils.Frameworks
}

//直接扫描
func StraightMod(config Config) {
	var wgs sync.WaitGroup
	targetChannel := generator(config)

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
	//fmt.Println(ip)
	var result = new(utils.Result)
	result.Ip = tc.ip
	result.Port = tc.port
	scan.Dispatch(result)
	//res := scan.SystemHttp(ip)

	if result.Open {
		Alivesum++
		if !Clean {
			fmt.Print(output(result, Output))
		}
		if FileHandle != nil {
			Datach <- output(result, FileOutput)
		}

	}
}

func SmartMod(config Config) {
	var taskname string
	if config.IP != "" {
		taskname = config.IP
	} else if config.IPlist != nil {
		taskname = fmt.Sprintf("%d cidrs", len(config.IPlist))
	}
	processLog(fmt.Sprintf("[*] SmartScan %s, Mod: %s", taskname, config.Mod))
	var wg sync.WaitGroup
	var temp sync.Map

	//go safeMap(&temp, aliveC)
	//var ipChannel chan string
	ipChannel := ipGenerator(config, &temp)

	var tcChannel chan targetConfig

	probeconfig := "[*] Smart probe ports:" + strings.Join(config.SmartPortList, ",") + ", "
	if config.Mod == "ss" {
		probeconfig += "Smart IP probe: " + config.IpProbe
	}
	processLog(probeconfig)

	tcChannel = tcGenerator(ipChannel, config.SmartPortList)
	scanPool, _ := ants.NewPoolWithFunc(config.Threads, func(i interface{}) {
		tc := i.(targetConfig)
		smartScan(tc, &temp, config.Mod)
		wg.Done()
	})

	defer scanPool.Release()
	for t := range tcChannel {
		wg.Add(1)
		_ = scanPool.Invoke(t)
	}
	wg.Wait()

	// 仅喷洒网段,不扫描
	if Noscan {
		return
	}

	var iplist []string
	temp.Range(func(key, value interface{}) bool {
		if config.Mod == "ss" {
			iplist = append(iplist, key.(string)+"/16")
		} else {
			iplist = append(iplist, key.(string)+"/24")
		}
		return true
	})
	if iplist == nil {
		return
	}
	sort.Strings(iplist)
	// 启发式扫描逐步降级,从喷洒B段到喷洒C段到默认扫描
	if config.Mod == "ss" {
		config.Mod = "s"
		for _, ip := range iplist {
			config.IP = ip
			processLog("[*] Spraying B class IP:" + ip)
			if config.SmartPort == "default" {
				config.SmartPortList = []string{"80"}
			}
			SmartMod(config)
		}
	} else {
		config.Mod = "default"
		config.IPlist = iplist
		StraightMod(config)
	}
}

func c_alived(ip string, temp *sync.Map) {
	s2ip := net.ParseIP(ip).To4()
	s2ip[3] = 0
	aliveC := s2ip.String()
	_, ok := temp.Load(aliveC)

	if !ok {
		temp.Store(aliveC, 1)
		fmt.Println("[*] Found " + ip + "/24")
		if FileHandle != nil && Noscan {
			Alivesum++
			Datach <- ip + "/24\n"
		}
	}
}

func b_alived(ip string, temp *sync.Map) {
	s2ip := net.ParseIP(ip).To4()
	s2ip[3] = 0
	s2ip[2] = 0
	aliveB := s2ip.String()

	_, ok := temp.Load(aliveB)
	if !ok {
		temp.Store(aliveB, 1)
		fmt.Println("[*] Found " + ip + "/16")
		if FileHandle != nil && Noscan {
			Alivesum++
			Datach <- ip + "/16\n"
		}
	}
}

func smartScan(tc targetConfig, temp *sync.Map, mod string) {
	var result = new(utils.Result)
	result.Ip = tc.ip
	result.Port = tc.port
	result.HttpStat = "s"

	scan.Dispatch(result)

	if result.Open {
		if mod == "ss" {
			b_alived(result.Ip, temp)
		} else {
			c_alived(result.Ip, temp)
		}
	}
}
