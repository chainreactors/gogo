package main

import (
	"flag"
	"fmt"
	"getitle/src/Scan"
	"getitle/src/core"
	"github.com/panjf2000/ants/v2"
	"os"
	"runtime"
	"strings"
	"time"
)

func main() {
	defer ants.Release()
	k := "yysy"
	// debug
	//f, _ := os.Create("cpu.txt")
	//pprof.StartCPUProfile(f)
	//defer pprof.StopCPUProfile()
	if !strings.Contains(strings.Join(os.Args, ""), k) {
		println("segment fault")
		os.Exit(0)
	}
	var config core.Config
	//默认参数信息
	flag.StringVar(&config.IP, "ip", "", "")
	flag.StringVar(&config.Ports, "p", "top1", "")
	key := flag.String("k", "", "")
	flag.StringVar(&config.List, "l", "", "")
	flag.IntVar(&config.Threads, "t", 4000, "")
	flag.StringVar(&config.Mod, "m", "default", "")
	flag.StringVar(&config.Typ, "n", "socket", "")
	flag.StringVar(&core.Output, "o", "full", "")
	flag.BoolVar(&config.Noscan, "no", false, "")
	flag.BoolVar(&core.Clean, "c", false, "")
	flag.StringVar(&core.FileOutput, "O", "json", "")
	flag.StringVar(&core.Filename, "f", "", "")
	delay := flag.Int("d", 2, "")
	exploit := flag.Bool("e", false, "")
	version := flag.Bool("v", false, "")
	isPortConfig := flag.Bool("P", false, "")
	formatoutput := flag.String("F", "", "")
	flag.Parse()
	// 密钥
	if *key != k {
		//rev()
		os.Exit(0)
	}
	// 输出Port config
	if *isPortConfig {
		core.Listportconfig()
		os.Exit(0)
	}
	// 格式化
	if *formatoutput != "" {
		core.FormatOutput(*formatoutput, config.Filename)
		os.Exit(0)
	}

	if config.IP == "" && config.List == "" && config.Mod != "a" {
		os.Exit(0)
	}
	// 存在文件输出则停止命令行输出
	if config.Filename != "" {
		core.Clean = !core.Clean
	}
	//windows系统默认协程数为2000
	OS := runtime.GOOS
	if config.Threads == 4000 && OS == "windows" {
		config.Threads = 2000
	}
	p := fmt.Sprintf("[*] Current goroutine: %d,", config.Threads)
	if !*version {
		p += "Version Scan Running, "
	} else {
		p += "Version Scan Closed, "
	}
	if *exploit {
		p += "Exploit Scan Running"
	} else {
		p += "Exploit Scan Closed"
	}
	println(p)
	starttime := time.Now()

	//初始化全局变量
	Scan.Delay = time.Duration(*delay)
	Scan.Exploit = *exploit
	Scan.Version = *version
	config = core.Init(config)
	core.RunTask(config)
	//关闭文件写入管道
	close(core.Datach)

	time.Sleep(time.Microsecond * 500)
	fmt.Println(fmt.Sprintf("\n[*] Alive sum: %d, Target sum : %d", Scan.Alivesum, Scan.Sum))
	fmt.Println("[*] Totally run: " + time.Since(starttime).String())

}
