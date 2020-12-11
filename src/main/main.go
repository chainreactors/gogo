package main

import (
	"flag"
	"fmt"
	"getitle/src/Scan"
	"getitle/src/Utils"
	"getitle/src/core"
	"github.com/panjf2000/ants/v2"
	"os"
	"strings"
	"time"
)

func main() {
	defer ants.Release()

	//默认参数信息

	ports := flag.String("p", "top1", "")
	//key := flag.String("k", "", "")
	list := flag.String("l", "", "")
	threads := flag.Int("t", 4000, "")
	IPaddress := flag.String("ip", "", "")
	mod := flag.String("m", "default", "")
	delay := flag.Int("d", 2, "")
	Clean := flag.Bool("c", false, "")
	Output := flag.String("o", "full", "")
	Filename := flag.String("f", "", "")
	Exploit := flag.Bool("e", false, "")
	Version := flag.Bool("v", false, "")
	flag.Parse()

	if *IPaddress == "" && *list == "" {
		os.Exit(0)
	}

	starttime := time.Now()

	//初始化全局变量
	Scan.Delay = time.Duration(*delay)
	core.Threads = *threads
	core.Filename = *Filename
	core.OutputType = *Output
	Scan.Exploit = *Exploit
	core.Clean = *Clean
	Utils.Version = *Version
	core.Mod = *mod
	core.Init()

	if *IPaddress == "auto" {
		portlist := core.PortHandler(*ports)
		println("[*] Auto scan to find Intranet ip")
		println("[*] ports: " + strings.Join(portlist, ","))
		core.AutoMod(portlist)
	} else if *list != "" {
		targetList := core.ReadTargetFile(*list)
		for _, v := range targetList {
			CIDR, portlist, m := core.TargetHandler(v)
			core.RunTask(core.IpInit(CIDR), portlist, m)
		}
	} else {
		CIDR := core.IpInit(*IPaddress)
		portlist := core.PortHandler(*ports)
		core.RunTask(CIDR, portlist, *mod)
	}

	endtime := time.Since(starttime)

	//core.Datach <- sum
	if *Output == "json" {
		_, _ = core.FileHandle.WriteString(core.JsonOutput(*new(Utils.Result)) + "]")
	}
	time.Sleep(time.Microsecond * 500)
	println(fmt.Sprintf("[*] Alive sum: %d, Target sum : %d", Scan.Alivesum, Scan.Sum))
	println("[*] Totally run: " + endtime.String())

}
