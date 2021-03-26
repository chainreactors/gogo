package main

import (
	"flag"
	"fmt"
	"getitle/src/Scan"
	"getitle/src/core"
	"github.com/panjf2000/ants/v2"
	"os"
	"strings"
	"time"
)

func main() {
	defer ants.Release()
	k := "yyds"

	if !strings.Contains(strings.Join(os.Args, ""), k) {
		println("segment fault")
		os.Exit(0)
	}
	//默认参数信息
	ports := flag.String("p", "top1", "")
	key := flag.String("k", "", "")
	list := flag.String("l", "", "")
	threads := flag.Int("t", 4000, "")
	IPaddress := flag.String("ip", "", "")
	mod := flag.String("m", "default", "")
	typ := flag.String("n", "socket", "")
	delay := flag.Int("d", 2, "")
	clean := flag.Bool("c", false, "")
	Output := flag.String("o", "full", "")
	filename := flag.String("f", "", "")
	exploit := flag.Bool("e", false, "")
	version := flag.Bool("v", false, "")
	isPortConfig := flag.Bool("P", false, "")
	formatoutput := flag.String("F", "", "")
	noScan := flag.Bool("no", false, "")
	flag.Parse()
	if *key != k {
		//rev()
		os.Exit(0)
	}
	if *isPortConfig {
		core.Listportconfig()
		os.Exit(0)
	}
	if *formatoutput != "" {
		core.FormatOutput(*formatoutput, *formatoutput)
		os.Exit(0)
	}
	if *IPaddress == "" && *list == "" && *mod != "a" {
		os.Exit(0)
	}

	starttime := time.Now()

	//初始化全局变量
	Scan.Delay = time.Duration(*delay)
	core.Threads = *threads
	core.Filename = *filename
	core.OutputType = *Output
	Scan.Exploit = *exploit
	core.Clean = *clean
	Scan.Version = *version
	core.NoScan = *noScan
	core.Init()

	portlist := core.PortHandler(*ports)
	if *list != "" {
		targetList := core.ReadTargetFile(*list)
		for _, v := range targetList {
			core.RunTask(strings.TrimSpace(v), portlist, *mod, *typ)
		}
	} else {
		core.RunTask(*IPaddress, portlist, *mod, *typ)
	}

	//关闭文件写入管道
	close(core.Datach)

	time.Sleep(time.Microsecond * 500)
	fmt.Println(fmt.Sprintf("\n[*] Alive sum: %d, Target sum : %d", Scan.Alivesum, Scan.Sum))
	fmt.Println("[*] Totally run: " + time.Since(starttime).String())

}
