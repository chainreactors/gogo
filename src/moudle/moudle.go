package moudle

import (
	"fmt"
	"getitle/src/Scan"
	"getitle/src/Utils"
	"github.com/panjf2000/ants/v2"
	"net"
	"strings"
	"sync"
)

//直接扫描
func StraightMod(target string, portlist []string, thread int) {
	var wgs sync.WaitGroup
	ipChannel := Ipgenerator(target)
	targetChannel := GenTarget(ipChannel, portlist)

	var Gentarget string

	// Use the pool with a function,
	// set 10 to the capacity of goroutine pool and 1 second for expired duration.
	p1, _ := ants.NewPoolWithFunc(thread, func(ipi interface{}) {
		StraightScan(ipi)
		wgs.Done()
	})
	defer p1.Release()

	for Gentarget = range targetChannel {
		wgs.Add(1)
		_ = p1.Invoke(Gentarget)
	}

	wgs.Wait()

}

func StraightScan(ipi interface{}) {
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

func SmartBMod(target string, temp []int, portlist []string) {
	var wg sync.WaitGroup
	AliveC := make(chan int, 100)

	go SafeSlice(temp, AliveC)

	ch := GenIP2(target, temp)

	SimpleList := []string{"80"}
	Tch := GenTarget(ch, SimpleList)

	var Gentarget string

	//old smartB

	//p2, _ := ants.NewPoolWithFunc(Threads, func(i interface{}) {
	//	//SmartScan(i,ResMap)
	//	SmartScan2(i, temp)
	//	wg.Done()
	//})

	// new smartB

	p2, _ := ants.NewPoolWithFunc(Threads, func(i interface{}) {
		//SmartScan(i,ResMap)
		SmartScan3(i, AliveC)
		wg.Done()
	})

	defer p2.Release()

	for Gentarget = range Tch {

		wg.Add(1)
		_ = p2.Invoke(Gentarget)
	}
	wg.Wait()

	var Alive = make([]string, 100, 100)
	var NextCTarget string

	start, _ := HandleIPAMASK(target)

	for k, v := range temp {

		if v > 0 {
			newC := Int2IP(start)
			HnewC := net.ParseIP(newC).To4()
			HnewC[2] = byte(k)
			NextCTarget = HnewC.String() + "/24"
			//fmt.Println(NextCTarget)
			Alive = append(Alive, NextCTarget)
		}

	}

	for _, alive := range Alive {
		if alive != "" {

			println("[*] Find " + alive)
			StraightMod(alive, portlist, Threads/2)

		}

	}

	//wg.Wait()

}

// slice 方式进行启发式扫描
func SmartScan2(ipi interface{}, Reslice []int) {
	target := ipi.(string)
	var result = new(Utils.Result)
	result.Ip = strings.Split(target, ":")[0]
	result.Port = strings.Split(target, ":")[1]

	*result = Scan.Dispatch(*result)

	if result.Stat == "OPEN" {

		s2ip := net.ParseIP(result.Ip).To4()
		c := s2ip[2]
		Reslice[c] += 1
	}
}

func SmartScan3(ipi interface{}, AliveCh chan int) {
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

func SafeSlice(temp []int, ch chan int) {
	for aliveC := range ch {

		temp[aliveC] += 1
	}
}

func SmartAMod(target string, portlist []string) {
	BSlice := make([][]int, 256)

	Tchan := GenBIP(target)
	var sum int = 0
	for i := range Tchan {
		CurB := i + "/16"
		println("[*] Processing:" + CurB)
		Temp := make([]int, 256)
		BSlice = append(BSlice, Temp)
		sum += 1
		SmartBMod(CurB, Temp, portlist)
	}
}
