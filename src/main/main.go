package main

import (
	"antest/src/http"
	"antest/src/moudle"
	"flag"
	"fmt"
	"github.com/panjf2000/ants/v2"
	"os"
	"strconv"
	"strings"
	"time"
)

type vars struct {
	ports string
	threads int
	IPaddress string
	mod string
	delay int
}
func main() {
	defer ants.Release()

	//默认参数信息

	ports := flag.String("p", "80,81,7001,9001,8080,8081,8000,8009,88,443,9999,7080,8070,9080,8082,8888,8089,5555", "ports")
	//ports := flag.String("port","80-8000","port")

	//ports := flag.String("port","21,22,23,25,443,444,445,464,465,468,487,488,496,500,512,513,514,515,517,518,519,520,521,525,526,530,531,532,533,535,538,540,543,544,546,547,548,554,556,563,565,587,610,611,612,616,631,636,674,694,749,750,751,752,754,760,765,767,808,871,873,901,953,992,993,994,995,1080,1109,1127,1178,1236,1300,1313,1433,1434,1494,1512,1524,1525,1529,1645,1646,1649,1701,1718,1719,1720,1758,1759,1789,1812,1813,1911,1985,1986,1997,2003,2049,2053,2102,2103,2104,2105,2150,2401,2430,2431,2432,2433,2600,2601,2602,2603,2604,2605,2606,2809,2988,3128,3130,3306,3346,3455,4011,4321,4444,4557,4559,5002,5232,5308,5354,5355,5432,5680,5999,6000,6010,6667,7000,7001,7002,7003,7004,7005,7006,7007,7008,7009,7100,7666,8008,8080,8081,9100,9359,9876,10080,10081,10082,10083,11371,11720,13720,13721,13722,13724,13782,13783,20011,20012,22273,22289,22305,22321,24554,26000,26208,27374,33434,60177,60179","max")

	threads := flag.Int("t", 4000, "threads")
	IPaddress := flag.String("ip", "", "IP地址 like 192.168.1.1/24")
	mod := flag.String("m", "straight", "扫描模式：straight or smartB")
	delay := flag.Int("d", 2, "超时,默认2s")


	t1 := time.Now()

	//server := "192.167.0.1/24"

	//portlist := []string{"80","81","7001","9001","8080","8081","8000","8009","88","443","9999","7080","8070","9080","8082","8888","8089","9001","5555","9001"}

	flag.Parse()
	init := vars{*ports,*threads,*IPaddress,*mod,*delay}
	init = Getbanner(init)
	fmt.Println(init.IPaddress)
	if init.IPaddress == "" {
		fmt.Println("Something wrong,Please use --help to see the usage")
		os.Exit(0)
	}

	//init the IP

	var portlist []string
	var rawportlist []string
	rawportlist = strings.Split(init.ports, ",")

	//生成端口列表 支持,和-
	for i := 0; i < len(rawportlist); i++ {
		if strings.Index(rawportlist[i], "-") > 0 {
			//fmt.Println(rawportlist[i])
			sf := strings.Split(rawportlist[i], "-")
			start, _ := strconv.Atoi(sf[0])

			fin, _ := strconv.Atoi(sf[1])

			for j := start; j <= fin; j++ {
				cur := strconv.Itoa(j)
				portlist = append(portlist, cur)
			}
		} else {
			portlist = append(portlist, rawportlist[i])
		}
	}

	//for m := 0 ; m < len(portlist); m++ {
	//	fmt.Println(portlist[m])
	//}

	// 原始的样子
	switch *mod {
	case "straight":
		//直接扫描
		moudle.StraightMod(init.IPaddress, portlist, init.threads, init.delay)
	case "smartB":
		//启发式扫描
		moudle.SmartBMod(init.IPaddress, portlist, init.threads, init.delay)
	}

	elapsed := time.Since(t1)
	fmt.Println("Totally run: ", elapsed)

	//输出扫描存活的数量和输出扫到有title的数量
	http.OutputAliveSum()
	http.OutputTitleSum()

}

func Getbanner(init vars)vars  {
	fmt.Println("*********  getitle 0.0.3 beta by Sangfor  *********")
	if init.IPaddress == ""{
		fmt.Println(
			"Usage of ./getitle:" +
				"\n  example ./getitle -ip 192.168.92.1 -p top2" +
				"\n  -d int			超时,默认2s (default 2)  " +
				"\n  -ip string		IP地址 like 192.168.1.1/24" +
				"\n  -m string        扫描模式：straight or smartB (default \"straight\")" +
				"\n  -p string        ports (default \"top1\")" +
				"\n     ports preset:   top1(default) 80,443,8080,7001,9001,8081,8082,8089,8000,8443" +
				"\n                     top2 80-89,443,7000-7009,9000-9009,8080-8090,8000-8009,8443,7080,8070,9080,8888,7777,9090,800,801,9999,10080" +
				"\n                     db 3306,1433,1521,5432,6379,11211,27017" +
				"\n                     rce 1090,1098,1099,4444,11099,47001,47002,10999,45000,45001,8686,9012,50500,4848,11111,4445,4786,5555,5556" +
				"\n                     win 53,88,135,139,389,445,3389,5985" +
				"\n  -t int        threads (default 4000)\n ",
		)
	}
	switch init.ports {
	case "top1":
		init.ports = "80,443,8080,7001,9001,8081,8082,8089,8000,8443,81"
	case "top2":
		init.ports = "80-89,443,7000-7009,9000-9009,8080-8090,8000-8009,8443,7080,8070,9080,8888,7777,9090,800,801,9999,10080"
	case "db":
		init.ports = "3306,1433,1521,5432,6379,11211,27017"
	case "rce":
		init.ports = "1090,1098,1099,4444,11099,47001,47002,10999,45000,45001,8686,9012,50500,4848,11111,4445,4786,5555,5556"
	case "win":
		init.ports = "53,88,135,139,389,445,3389,5985"
	default:
		init.ports = "80,443,8080,7001,9001,8081,8082,8089,8000,8443,81"
	}
	return init
}
