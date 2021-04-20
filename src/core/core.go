package core

import (
	"fmt"
	"getitle/src/Scan"
	"getitle/src/Utils"
	"github.com/panjf2000/ants/v2"
	"net"
	"sync"
	"time"
)

type TargetConfig struct {
	ip   string
	port string
}

//直接扫描
func StraightMod(config Config) {
	var wgs sync.WaitGroup
	var ipChannel chan string
	ipChannel = ipGenerator(config, nil)
	targetChannel := tcGenerator(ipChannel, config.Portlist)

	// Use the pool with a function,
	// set 10 to the capacity of goroutine pool and 1 second for expired duration.
	scanPool, _ := ants.NewPoolWithFunc(config.Threads, func(i interface{}) {
		tc := i.(TargetConfig)
		defaultScan(tc)
		wgs.Done()
	})
	defer scanPool.Release()

	for t := range targetChannel {
		wgs.Add(1)
		_ = scanPool.Invoke(t)
	}

	wgs.Wait()

}

func defaultScan(tc TargetConfig) {
	//fmt.Println(ip)
	var result = new(Utils.Result)
	result.Ip = tc.ip
	result.Port = tc.port
	Scan.Dispatch(result)
	//res := Scan.SystemHttp(ip)

	if result.Stat != "" {
		if !Clean {
			fmt.Print(output(result, Output))
		}
		if FileHandle != nil {
			Datach <- output(result, FileOutput)
		}

	}
}

func safeMap(temp *sync.Map, ch chan string) {
	for aliveC := range ch {
		v, ok := temp.Load(aliveC)
		if ok {
			count := v.(int) + 1
			temp.Store(aliveC, count)

			//temp[aliveC] = 1
		} else {
			temp.Store(aliveC, 1)
			fmt.Println("[*] Find " + aliveC + "/24")
			//temp[aliveC] += 1
		}
	}
}

func SmartBMod(config Config) {
	var wg sync.WaitGroup
	var temp sync.Map

	aliveC := make(chan string)
	go safeMap(&temp, aliveC)
	var ipChannel chan string
	ipChannel = ipGenerator(config, &temp)
	// 选择ip生成器

	var tcChannel chan TargetConfig

	if config.Typ == "icmp" || config.Typ == "i" {
		fmt.Println("[*] current Protocol: ICMP")
		tcChannel = tcGenerator(ipChannel, []string{"icmp"})
	} else {
		fmt.Println("[*] current Protocol: Socket")
		tcChannel = tcGenerator(ipChannel, []string{"80"})
	}

	scanPool, _ := ants.NewPoolWithFunc(config.Threads, func(i interface{}) {
		tc := i.(TargetConfig)
		smartScan(tc, aliveC)
		wg.Done()
	})

	defer scanPool.Release()
	for t := range tcChannel {
		wg.Add(1)
		_ = scanPool.Invoke(t)
	}
	wg.Wait()
	time.Sleep(2 * time.Second)
	close(aliveC)

	if !config.Noscan {
		temp.Range(func(key, value interface{}) bool {
			if value.(int) > 0 {
				fmt.Println("[*] " + Utils.GetCurtime() + " Processing:" + key.(string) + "/24")
				var tmpconfig = config
				tmpconfig.IP = key.(string) + "/24"
				StraightMod(tmpconfig)
				//每个C段同步一次数据
				FileHandle.Sync()
			}
			return true
		})
	}

}

func smartScan(tc TargetConfig, AliveCh chan string) {
	var result = new(Utils.Result)
	result.Ip = tc.ip
	result.Port = tc.port

	Scan.Dispatch(result)

	if result.Stat == "OPEN" {
		s2ip := net.ParseIP(result.Ip).To4()
		s2ip[3] = 1
		AliveCh <- s2ip.String()
	}
}

func SmartAMod(config Config) {
	btargetChannel := bipGenerator(config.IP)
	for i := range btargetChannel {
		fmt.Println("[*]" + Utils.GetCurtime() + "Processing Bclass IP:" + i + "/16")
		var tmpconfig = config
		tmpconfig.IP = i + "/16"
		SmartBMod(tmpconfig)
	}
}
