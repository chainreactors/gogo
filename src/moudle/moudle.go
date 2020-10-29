package moudle

import (
	"fmt"
	"getitle/src/Scan"
	"github.com/panjf2000/ants/v2"
	"net"
	"strings"
	"sync"
	"time"
)

var lock sync.Mutex
var Outputforamt string
//直接扫描
func StraightMod(target string, portlist []string, Threads int, Delay time.Duration) {
	var wgs sync.WaitGroup
	ch := GenIP(target)

	Tch := GenTarget(ch, portlist)

	var Gentarget string

	// Use the pool with a function,
	// set 10 to the capacity of goroutine pool and 1 second for expired duration.
	p1, _ := ants.NewPoolWithFunc(Threads, func(ipi interface{}) {
		StraightScan(ipi, Delay)
		wgs.Done()
	})
	defer p1.Release()

	for Gentarget = range Tch {
		wgs.Add(1)
		_ = p1.Invoke(Gentarget)
	}

	wgs.Wait()
}

func StraightScan(ipi interface{}, Delay time.Duration) {
	target := ipi.(string)
	//fmt.Println(ip)
	ip:= strings.Split(target,":")[0]
	port := strings.Split(target,":")[1]
	res := Scan.Dispatch(ip,port, Delay)
	//res := Scan.SystemHttp(ip)
	if res["stat"] == "CLOSE" {

	} else {
		output(res,Outputforamt)
	}
}

func SmartBMod(target string, temp []int, portlist []string, Threads int, Delay time.Duration) {
	var wg sync.WaitGroup
	//var wg2 sync.WaitGroup
	ch := GenIP2(target, temp)

	SimpleList := []string{"80"}
	Tch := GenTarget(ch, SimpleList)

	var Gentarget string
	//ResMap := GetMap()

	p2, _ := ants.NewPoolWithFunc(Threads, func(i interface{}) {
		//SmartScan(i,ResMap)
		SmartScan2(i, temp, Delay)
		wg.Done()
	})
	defer p2.Release()

	for Gentarget = range Tch {
		//fmt.Println(target)
		wg.Add(1)
		_ = p2.Invoke(Gentarget)
	}
	wg.Wait()

	var Alive = make([]string, 100, 100)
	var NextCTarget string

	start, _ := HandleIPAMASK(target)

	for k, v := range temp {

		if v > 0 {
			newC := MyInt2IP(start)
			HnewC := net.ParseIP(newC).To4()
			HnewC[2] = byte(k)
			NextCTarget = HnewC.String() + "/24"
			//fmt.Println(NextCTarget)
			Alive = append(Alive, NextCTarget)
		}

	}

	for _, alive := range Alive {
		if alive != "" {

			fmt.Println(alive)
			StraightMod(alive, portlist, Threads/2, Delay)

		}

	}

	//wg.Wait()

}

// slice 方式进行启发式扫描
func SmartScan2(ipi interface{}, Reslice []int, Delay time.Duration) {
	target := ipi.(string)
	ip:= strings.Split(target,":")[0]
	port := strings.Split(target,":")[1]

	res := Scan.Dispatch(ip,port, Delay)
	if res["stat"] == "OPEN" {

		ip = strings.Split(ip, ":")[0]
		s2ip := net.ParseIP(ip).To4()
		c := s2ip[2]
		Reslice[c] += 1
	}
}

func SmartAMod(target string, portlist []string, Threads int, Delay time.Duration) {
	BSlice := make([][]int, 256)

	Tchan := GenBIP(target)
	var sum int = 0
	for i := range Tchan {
		CurB := i + "/16"
		fmt.Println("now start:" + CurB)
		Temp := make([]int, 256)
		BSlice = append(BSlice, Temp)
		sum += 1
		SmartBMod(CurB, Temp, portlist, Threads, Delay)
	}
}
