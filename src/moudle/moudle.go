package moudle

import (
	"antest/src/http"
	"fmt"
	"github.com/panjf2000/ants/v2"
	"net"
	"strings"
	"sync"
)

var sum int = 0
var lock sync.Mutex

func StraightMod(target string, portlist []string, Threads int) {
	var wgs sync.WaitGroup
	ch := GenIP(target)

	Tch := GenTarget(ch, portlist)

	var Gentarget string

	// Use the pool with a function,
	// set 10 to the capacity of goroutine pool and 1 second for expired duration.
	p1, _ := ants.NewPoolWithFunc(Threads, func(j interface{}) {
		StraightScan(j)
		wgs.Done()
	})
	defer p1.Release()

	for Gentarget = range Tch {
		wgs.Add(1)
		_ = p1.Invoke(Gentarget)
	}

	wgs.Wait()
}

func StraightScan(ipi interface{}) {
	ip := ipi.(string)
	//fmt.Println(ip)
	//res := http.MyHttpSocket(ip)
	res := http.SystemHttp(ip)
	if res == "" {

	} else {
		fmt.Println(res)
	}
}

func SmartBMod(target string, portlist []string, Threads int) {
	var wg sync.WaitGroup
	//var wg2 sync.WaitGroup
	ch := GenIP2(target)

	SimpleList := []string{"80"}
	Tch := GenTarget(ch, SimpleList)

	var Gentarget string
	//ResMap := GetMap()

	ResSlice := GetSlice()

	p2, _ := ants.NewPoolWithFunc(Threads, func(i interface{}) {
		//SmartScan(i,ResMap)
		SmartScan2(i, ResSlice)
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

	for k, v := range ResSlice {

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
			//fmt.Println(alive)
			//go func(a string){

			//wg.Add(1)
			fmt.Println(alive)
			StraightMod(alive, portlist, Threads/2)
			//wg.Done()
			//}(alive)
		}

	}

	//wg.Wait()

}

// slice 方式进行启发式扫描
func SmartScan2(ipi interface{}, Reslice []int) {
	ip := ipi.(string)
	res := http.MyHttpSocket(ip)
	if res == "" {

	} else {
		ip = strings.Split(ip, ":")[0]
		s2ip := net.ParseIP(ip).To4()
		c := s2ip[2]
		Reslice[c] += 1
		//fmt.Println(res)
	}

}

func OutputBsum() int {
	return sum
}
