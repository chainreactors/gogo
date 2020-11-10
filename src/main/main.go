package main

import (
	"flag"
	"getitle/src/Scan"
	"getitle/src/Utils"
	"getitle/src/moudle"
	"github.com/panjf2000/ants/v2"
	"strconv"
	"strings"
	"time"
)

func main() {
	defer ants.Release()

	//默认参数信息

	ports := flag.String("p", "top1", "")
	//ports := flag.String("port","80-8000","port")
	key := flag.String("k", "", "")
	//ports := flag.String("port","21,22,23,25,443,444,445,464,465,468,487,488,496,500,512,513,514,515,517,518,519,520,521,525,526,530,531,532,533,535,538,540,543,544,546,547,548,554,556,563,565,587,610,611,612,616,631,636,674,694,749,750,751,752,754,760,765,767,808,871,873,901,953,992,993,994,995,1080,1109,1127,1178,1236,1300,1313,1433,1434,1494,1512,1524,1525,1529,1645,1646,1649,1701,1718,1719,1720,1758,1759,1789,1812,1813,1911,1985,1986,1997,2003,2049,2053,2102,2103,2104,2105,2150,2401,2430,2431,2432,2433,2600,2601,2602,2603,2604,2605,2606,2809,2988,3128,3130,3306,3346,3455,4011,4321,4444,4557,4559,5002,5232,5308,5354,5355,5432,5680,5999,6000,6010,6667,7000,7001,7002,7003,7004,7005,7006,7007,7008,7009,7100,7666,8008,8080,8081,9100,9359,9876,10080,10081,10082,10083,11371,11720,13720,13721,13722,13724,13782,13783,20011,20012,22273,22289,22305,22321,24554,26000,26208,27374,33434,60177,60179","max")

	threads := flag.Int("t", 4000, "")
	IPaddress := flag.String("ip", "", "")
	mod := flag.String("m", "default", "")
	delay := flag.Int("d", 2, "")
	Output := flag.String("o", "full", "")
	Filename := flag.String("f", "", "")
	Exploit := flag.Bool("e", false, "")
	OutputT := flag.Bool("j", false, "")

	flag.Parse()
	//Scan.Outp = *Output
	t1 := time.Now()

	moudle.Outputforamt = *Output
	moudle.IsJson = *OutputT
	//set config
	Scan.Delay = time.Duration(*delay)
	moudle.Threads = *threads
	moudle.Filename = *Filename
	Scan.Exploit = *Exploit
	//init the IP
	CIDR := moudle.Init(*IPaddress, *key)
	portlist := moudle.PortHandler(*ports)

	println("[*] Start Scan " + CIDR)

	switch *mod {
	case "default":
		//直接扫描
		moudle.StraightMod(CIDR, portlist, moudle.Threads)
	case "s", "smart":
		//启发式扫描
		temp := make([]int, 256)
		mask, _ := strconv.Atoi(strings.Split(CIDR, "/")[1])
		if mask == 16 {
			moudle.SmartBMod(CIDR, temp, portlist)
		} else if mask < 16 {
			moudle.SmartAMod(CIDR, portlist)
		} else {
			println("[-] mod s :please check your mask < 16")
		}
	}

	elapsed := time.Since(t1)

	sum := "[*] Alive sum: " + strconv.Itoa(Scan.Alivesum)
	//moudle.Datach <- sum
	if moudle.IsJson {
		res := new(Utils.Result)
		Sres := moudle.JsonReturn(*res)
		moudle.FileHandle.WriteString(Sres + "]")
	} else {
		moudle.FileHandle.WriteString(sum)
	}

	time.Sleep(time.Microsecond * 500)
	println(sum)
	println("[*] Totally run: " + elapsed.String())

}
