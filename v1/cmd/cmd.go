package cmd

import (
	"flag"
	"fmt"
	. "getitle/v1/internal/core"
	. "getitle/v1/internal/scan"
	"getitle/v1/pkg"
	"github.com/panjf2000/ants/v2"
	"os"
	"strings"
)

var ver = ""
var k = ""

func CMD() {
	defer ants.Release()
	//connected = checkconn()
	if !strings.Contains(strings.Join(os.Args, ""), k) {
		//inforev()
		exit()
	}
	runner := NewRunner()
	//默认参数信息
	// INPUT
	flag.StringVar(&runner.config.IP, "ip", "", "")
	flag.StringVar(&runner.Ports, "p", "", "")
	flag.StringVar(&runner.config.ListFile, "l", "", "")
	flag.StringVar(&runner.config.JsonFile, "j", "", "")
	flag.StringVar(&runner.WorkFlowName, "w", "", "")
	flag.BoolVar(&runner.config.IsListInput, "L", false, "")
	flag.BoolVar(&runner.config.IsJsonInput, "J", false, "")
	flag.BoolVar(&runner.IsWorkFlow, "W", false, "")

	// SMART
	flag.StringVar(&runner.config.SmartPort, "sp", "default", "")
	flag.StringVar(&runner.config.IpProbe, "ipp", "default", "")
	flag.BoolVar(&runner.config.NoSpray, "ns", false, "")
	flag.BoolVar(&runner.NoScan, "no", false, "")

	// OUTPUT
	flag.StringVar(&runner.config.Filename, "f", "", "")
	flag.StringVar(&Opt.FilePath, "path", "", "")
	//flag.StringVar(&runner.config.ExcludeIPs, "eip", "", "")
	flag.StringVar(&Opt.Output, "o", "full", "")
	flag.BoolVar(&runner.Clean, "c", false, "")
	flag.StringVar(&runner.FileOutput, "O", "default", "")
	flag.BoolVar(&runner.Quiet, "q", false, "")
	flag.Var(&runner.filters, "filter", "")
	flag.StringVar(&runner.FormatterFilename, "F", "", "")
	flag.BoolVar(&runner.AutoFile, "af", false, "")
	flag.BoolVar(&runner.HiddenFile, "hf", false, "")
	flag.BoolVar(&runner.Compress, "C", false, "")

	// CONFIG
	flag.IntVar(&runner.config.Threads, "t", 0, "")
	flag.StringVar(&runner.config.Mod, "m", "default", "")
	flag.BoolVar(&runner.config.PortSpray, "s", false, "")
	flag.BoolVar(&runner.Ping, "ping", false, "")
	flag.BoolVar(&runner.Arp, "arp", false, "")
	flag.StringVar(&runner.iface, "iface", "eth0", "")
	flag.IntVar(&RunOpt.Delay, "d", 2, "")
	flag.IntVar(&RunOpt.HttpsDelay, "D", 2, "")
	flag.StringVar(&RunOpt.SuffixStr, "suffix", "", "")
	flag.Var(&runner.payloads, "payload", "")
	flag.Var(&runner.extract, "extract", "")
	flag.StringVar(&runner.extracts, "extracts", "", "")
	flag.BoolVar(&runner.Version, "v", false, "")
	flag.BoolVar(&runner.Version2, "vv", false, "")
	flag.BoolVar(&runner.Exploit, "e", false, "")
	flag.StringVar(&runner.ExploitName, "E", "none", "")
	flag.StringVar(&runner.ExploitFile, "ef", "", "")

	// OTHER
	key := flag.String("k", "", "")
	flag.StringVar(&runner.Printer, "P", "", "")
	flag.BoolVar(&runner.NoUpload, "nu", false, "")
	flag.StringVar(&runner.UploadFile, "uf", "", "")
	flag.BoolVar(&runner.Ver, "version", false, "")
	flag.BoolVar(&runner.Debug, "debug", false, "")

	flag.Usage = func() { exit() }
	flag.Parse()
	// 密钥
	if *key != k {
		//inforev()
		exit()
	} else {
		pkg.Key = []byte(*key)
	}

	if ok := runner.preInit(); !ok {
		os.Exit(0)
	}
	runner.init()
	runner.run()

}

type Value interface {
	String() string
	Set(string) error
}

type arrayFlags []string

// Value ...
func (i *arrayFlags) String() string {
	return fmt.Sprint(*i)
}

// Set 方法是flag.Value接口, 设置flag Value的方法.
// 通过多个flag指定的值， 所以我们追加到最终的数组上.
func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}
