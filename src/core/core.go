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

var NoScan bool

//直接扫描
func StraightMod(target string, portlist []string) {
	var wgs sync.WaitGroup
	ipChannel := ipGenerator(target, "default", nil)
	targetChannel := tcGenerator(ipChannel, portlist)

	// Use the pool with a function,
	// set 10 to the capacity of goroutine pool and 1 second for expired duration.
	scanPool, _ := ants.NewPoolWithFunc(Threads, func(i interface{}) {
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
			fmt.Print(output(result, OutputType))
		}
		if O2File {
			Datach <- output(result, OutputType)
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
			println("[*] Find " + aliveC)
			//temp[aliveC] += 1
		}
	}
}

func SmartBMod(target string, portlist []string, mod string, typ string) {
	var wg sync.WaitGroup
	var temp sync.Map

	aliveC := make(chan string)
	go safeMap(&temp, aliveC)

	// 选择ip生成器
	ipChannel := ipGenerator(target, mod, &temp)
	var tcChannel chan TargetConfig

	if typ == "icmp" || typ == "i" {
		println("[*] current Protocol: ICMP")
		tcChannel = tcGenerator(ipChannel, []string{"icmp"})
	} else {
		println("[*] current Protocol: Socket")
		tcChannel = tcGenerator(ipChannel, []string{"80"})
	}

	scanPool, _ := ants.NewPoolWithFunc(Threads, func(i interface{}) {
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
	if !NoScan {
		temp.Range(func(key, value interface{}) bool {
			if value.(int) > 0 {
				println("[*] " + Utils.GetCurtime() + " Processing:" + key.(string) + "/24")
				StraightMod(key.(string)+"/24", portlist)
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

func SmartAMod(target string, portlist []string, mod string, typ string) {
	btargetChannel := bipGenerator(target)
	for i := range btargetChannel {
		println("[*]" + Utils.GetCurtime() + "Processing Bclass IP:" + i + "/16")
		SmartBMod(i+"/16", portlist, mod, typ)
	}
}

//func AutoMod(portlist []string) {
//	var wgs sync.WaitGroup
//	//if target {
//	autoIcmpChannel := ipGenerator("auto","defalut",nil)
//	var tcChannel chan TargetConfig
//	if Mod == "s" {
//		println("[*] current Mod : Socket")
//		tcChannel = tcGenerator(autoIcmpChannel, []string{"80"})
//	} else {
//		println("[*] current Mod : ICMP")
//		tcChannel = tcGenerator(autoIcmpChannel, []string{"icmp"})
//	}
//
//	var temp sync.Map
//	aliveC := make(chan string)
//	go safeMap(&temp, aliveC)
//
//	//go safeMap(temp, aliveC)
//	// Use the pool with a function,
//	// set 10 to the capacity of goroutine pool and 1 second for expired duration.
//	scanPool, _ := ants.NewPoolWithFunc(Threads, func(i interface{}) {
//		tc := i.(TargetConfig)
//		smartScan(tc, aliveC)
//		wgs.Done()
//	})
//	defer scanPool.Release()
//
//	for t := range tcChannel {
//		wgs.Add(1)
//		_ = scanPool.Invoke(t)
//	}
//	wgs.Wait()
//	time.Sleep(2 * time.Second)
//	close(aliveC)
//
//	temp.Range(func(key, value interface{}) bool {
//		if value.(int) > 0 {
//			println("[*] Processing:" + key.(string) + "/24")
//			StraightMod(key.(string)+"/24", portlist)
//		}
//		return true
//	})
//
//}
