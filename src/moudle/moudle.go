package moudle

import (
	"fmt"
	"getitle/src/Scan"
	"getitle/src/Utils"
	"github.com/panjf2000/ants/v2"
	"net"
	"strconv"
	"strings"
	"sync"
)

//直接扫描
func StraightMod(target string, portlist []string, thread int) {
	var wgs sync.WaitGroup
	ipChannel := Ipgenerator(target)
	targetChannel := TargetGenerator(ipChannel, portlist)

	var Gentarget string

	// Use the pool with a function,
	// set 10 to the capacity of goroutine pool and 1 second for expired duration.
	p1, _ := ants.NewPoolWithFunc(thread, func(ipi interface{}) {
		DefaultScan(ipi)
		wgs.Done()
	})
	defer p1.Release()

	for Gentarget = range targetChannel {
		wgs.Add(1)
		_ = p1.Invoke(Gentarget)
	}

	wgs.Wait()

}

func DefaultScan(ipi interface{}) {
	target := ipi.(string)
	//fmt.Println(ip)
	var result = new(Utils.Result)
	result.Ip = strings.Split(target, ":")[0]
	result.Port = strings.Split(target, ":")[1]
	*result = Scan.Dispatch(*result)
	//res := Scan.SystemHttp(ip)

	if result.Stat != "" {
		fmt.Print(output(*result, OutputType))
		if O2File {
			Datach <- output(*result, OutputType)
		}

	}
}

func SafeSlice(temp []int, ch chan int, baseip string) {
	for aliveC := range ch {
		temp[aliveC] += 1
		if temp[aliveC] == 1 {
			println("[*] Find " + baseip + "." + strconv.Itoa(aliveC) + ".0/24")
		}
	}
}

func SmartBMod(target string, portlist []string) {
	var wg sync.WaitGroup
	temp := make([]int, 256)
	aliveC := make(chan int, 256)
	ip_B := strings.Join(strings.Split(target, ".")[:2], ".")
	go SafeSlice(temp, aliveC, ip_B)

	ipChannel := SmartIpGenerator(target, temp)

	targetChannel := TargetGenerator(ipChannel, []string{"80"})

	//old smartB

	//scanPool, _ := ants.NewPoolWithFunc(Threads, func(i interface{}) {
	//	//SmartScan(i,ResMap)
	//	SmartScan2(i, temp)
	//	wg.Done()
	//})

	// new smartB

	scanPool, _ := ants.NewPoolWithFunc(Threads, func(t interface{}) {
		SmartScan(t, aliveC)
		wg.Done()
	})

	defer scanPool.Release()

	for t := range targetChannel {

		wg.Add(1)
		_ = scanPool.Invoke(t)
	}
	wg.Wait()
	close(aliveC)

	ip_B = ip_B + ".0.0"
	tmpip := net.ParseIP(ip_B).To4()

	for k, v := range temp {

		if v > 0 {
			tmpip[2] = byte(k)
			println("[*] Processing:" + tmpip.String() + "/24")
			StraightMod(tmpip.String()+"/24", portlist, Threads)
		}

	}

	//wg.Wait()

}

// slice 方式进行启发式扫描
//func SmartScan2(ipi interface{}, Reslice []int) {
//	target := ipi.(string)
//	var result = new(Utils.Result)
//	result.Ip = strings.Split(target, ":")[0]
//	result.Port = strings.Split(target, ":")[1]
//
//	*result = Scan.Dispatch(*result)
//
//	if result.Stat == "OPEN" {
//
//		s2ip := net.ParseIP(result.Ip).To4()
//		c := s2ip[2]
//		Reslice[c] += 1
//	}
//}

func SmartScan(ipi interface{}, AliveCh chan int) {
	target := ipi.(string)
	var result = new(Utils.Result)
	result.Ip = strings.Split(target, ":")[0]
	result.Port = strings.Split(target, ":")[1]

	*result = Scan.Dispatch(*result)

	if result.Stat == "OPEN" {
		s2ip := net.ParseIP(result.Ip).To4()
		c := s2ip[2]
		AliveCh <- int(c)
	}
}

func SmartAMod(target string, portlist []string) {
	btargetChannel := GenBIP(target)
	for i := range btargetChannel {
		println("[*] Processing Bclass IP:" + i + "/16")
		SmartBMod(i+"/16", portlist)
	}
}
