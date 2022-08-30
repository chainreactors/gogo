package cmd

import (
	"flag"
	"fmt"
	"github.com/chainreactors/gogo/v1/internal/core"
	"github.com/chainreactors/gogo/v1/internal/plugin"
	"github.com/chainreactors/gogo/v1/pkg"
	"github.com/chainreactors/logs"
	"os"
)

var ver = ""
var k = ""

func CMD() {
	runner := NewRunner()
	key := flag.String("k", "", "key")
	//默认参数信息
	// INPUT
	flag.StringVar(&runner.config.IP, "ip", "", "IP/CIDR, support comma-split ip/cidr, e.g. 192.168.1.1/24,172.16.1.1/24")
	flag.StringVar(&runner.config.Ports, "p", "", "PORT, support comma-split preset(`-P port` show all preset), range, alias port, e.g. top2,mysql,12345,10000-10100,oxid,smb")
	flag.StringVar(&runner.config.ListFile, "l", "", "File,  list of IP/CIDR")
	flag.StringVar(&runner.config.JsonFile, "j", "", "File,  previous results file e.g. -j 1.dat1 or list of colon-split ip:port, e.g. 123.123.123.123:123")
	flag.StringVar(&runner.WorkFlowName, "w", "", "String, workflow name(`-P workflow` show all workflow)")
	flag.BoolVar(&runner.config.IsListInput, "L", false, "same as -l, input from stdin")
	flag.BoolVar(&runner.config.IsJsonInput, "J", false, "same as -j, input from stdin")
	flag.BoolVar(&runner.IsWorkFlow, "W", false, "same as -w, input from stdin")

	// SMART
	flag.StringVar(&runner.config.SmartPort, "sp", "default", "smart port probe")
	flag.StringVar(&runner.config.IpProbe, "ipp", "default", "smart ip probe")
	flag.BoolVar(&runner.config.NoSpray, "ns", false, "force to close auto-spray")
	flag.BoolVar(&runner.NoScan, "no", false, "force to close default-scan on smart mod")

	// OUTPUT
	flag.StringVar(&runner.config.Filename, "f", "", "FILE, output filename")
	flag.StringVar(&runner.config.FilePath, "path", "", "PATH, output file path")
	//flag.StringVar(&runner.config.ExcludeIPs, "eip", "", "")
	flag.StringVar(&runner.Outputf, "o", "default", "String,cmdline output format")
	flag.BoolVar(&runner.Clean, "c", false, "close stdout output")
	flag.StringVar(&runner.FileOutputf, "O", "default", "String, file output format")
	flag.BoolVar(&runner.Quiet, "q", false, "close log output")
	flag.Var(&runner.filters, "filter", "String, filter result e.g -filter port::22")
	flag.StringVar(&runner.FormatterFilename, "F", "", "String, Scanned result to be formatted")
	flag.BoolVar(&runner.AutoFile, "af", false, "auto choice filename")
	flag.BoolVar(&runner.HiddenFile, "hf", false, "auto choice hidden filename")
	flag.BoolVar(&runner.config.Compress, "C", false, "close compress output file")

	// CONFIG
	flag.IntVar(&runner.config.Threads, "t", 0, "threads")
	flag.StringVar(&runner.config.Mod, "m", "default", "scan mod")
	flag.BoolVar(&runner.config.PortSpray, "s", false, "open port spray generator")
	flag.BoolVar(&runner.Ping, "ping", false, "alive pre-scan")
	//flag.BoolVar(&runner.Arp, "arp", false, "")
	//flag.StringVar(&runner.iface, "iface", "eth0", "")
	flag.IntVar(&plugin.RunOpt.Delay, "d", 2, "Int, timeout")
	flag.IntVar(&plugin.RunOpt.HttpsDelay, "D", 2, "Int, https timeout")
	flag.StringVar(&plugin.RunOpt.SuffixStr, "suffix", "", "String, add base-scan urlpath")
	flag.Var(&runner.payloads, "payload", "String, nuclei payload replace, e.g. -payload username=admin")
	flag.Var(&runner.extract, "extract", "Regexp, extract response to extracted file")
	flag.StringVar(&runner.extracts, "extracts", "", "String,comma-split preset extract regexps name, e.g. ip,url")
	flag.BoolVar(&runner.Version, "v", false, "active finger scan")
	//flag.BoolVar(&runner.Version2, "vv", false, "")
	flag.BoolVar(&runner.Exploit, "e", false, "auto poc scan")
	flag.StringVar(&runner.ExploitName, "E", "none", "specify poc name")
	flag.StringVar(&runner.ExploitFile, "ef", "", "specify poc file")

	// OTHER
	flag.StringVar(&runner.Printer, "P", "", "Print port/workflow/nuclei")
	//flag.BoolVar(&runner.NoUpload, "nu", false, "")
	//flag.StringVar(&runner.UploadFile, "uf", "", "")
	flag.BoolVar(&runner.Ver, "version", false, "show version")
	flag.BoolVar(&runner.Debug, "debug", false, "print debug")
	flag.BoolVar(&core.Opt.PluginDebug, "plugindebug", false, "print plugin debug stack")
	flag.StringVar(&runner.Proxy, "proxy", "", "specify http/socks5 proxy")
	//flag.Usage = func() { exit() }
	flag.Usage = func() { core.PrintHelp() }

	flag.Parse()
	// 密钥
	pkg.Key = []byte(*key)

	if ok := runner.preInit(); !ok {
		os.Exit(0)
	}
	runner.init()
	runner.run()

	logs.Log.Close(true)
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
