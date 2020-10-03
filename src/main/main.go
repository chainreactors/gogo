package main

import (
	"antest/src/http"
	"antest/src/moudle"
	"flag"
	"fmt"
	"github.com/panjf2000/ants/v2"
	"os"
	"strings"
	"time"
)

func main() {
	defer ants.Release()

	ports := flag.String("port", "80,81,7001,9001,8080,8081,8000,8009,88,443,9999,7080,8070,9080,8082,8888,8089,9001,5555,9001", "ports")
	//ports := flag.String("port","80","port")
	Threads := flag.Int("threads", 4000, "threads")
	IPAddress := flag.String("ip", "124.127.43.35/24", "IP地址 like 192.168.1.1/24")
	Mod := flag.String("m", "straight", "扫描模式：straight or smartB")

	t1 := time.Now()
	//server := "192.167.0.1/24"

	//portlist := []string{"80","81","7001","9001","8080","8081","8000","8009","88","443","9999","7080","8070","9080","8082","8888","8089","9001","5555","9001"}

	flag.Parse()

	if *IPAddress == "" {
		fmt.Println("Something wrong,Please use --help to see the usage")
		os.Exit(0)
	}

	//init the IP

	portlist := strings.Split(*ports, ",")

	switch *Mod {
	case "straight":
		moudle.StraightMod(*IPAddress, portlist, *Threads)
	case "smartB":
		moudle.SmartBMod(*IPAddress, portlist, *Threads)
	}

	elapsed := time.Since(t1)
	fmt.Println("Totally run: ", elapsed)

	http.OutputAliveSum()
	http.OutputTitleSum()

}
