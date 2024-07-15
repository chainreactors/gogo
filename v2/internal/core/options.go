package core

var (
	LinuxDefaultThreads        = 4000
	WindowsMacDefaultThreads   = 1000
	DefaultIpProbe             = []uint{1, 254}
	DefaultSmartPortProbe      = []string{"80", "icmp"}
	DefaultSuperSmartPortProbe = []string{"icmp", "23", "80"}
)

type InputOption struct {
	IP                string `short:"i" long:"ip" description:"IP/CIDR, support comma-split ip/cidr, e.g. 192.168.1.1/24,172.16.1.1/24"`
	Exclude           string `long:"exclude" description:"IP/CIDR, exclude IP/CIDR, support comma-split"`
	ExcludeList       string `long:"exclude-file" description:"File, exclude IP/CIDR filename"`
	Ports             string `short:"p" long:"port" default:"top1" description:"Port, support comma-split preset('-P port' show all preset), range, alias port, e.g. top2,mysql,12345,10000-10100,oxid,smb"`
	PortConfig        string `long:"port-config" description:"File,custom port config file"`
	ListFile          string `short:"l" long:"list" description:"File, list of IP/CIDR"`
	IsListInput       bool   `short:"L" description:"Bool, same as -l, input from stdin"`
	JsonFile          string `short:"j" long:"json" description:"File, previous results file e.g. -j 1.dat1 or list of colon-split ip:port, e.g. 123.123.123.123:123"`
	IsJsonInput       bool   `short:"J" description:"Bool, same as -j, input from stdin"`
	FilterOr          bool   `long:"filter-or" description:"FilterOr"`
	WorkFlowName      string `short:"w" long:"workflow" description:"String, workflow name('-P workflow' show all workflow)"`
	IsWorkFlow        bool   `short:"W" description:"Bool, same as -w, input from stdin"`
	FormatterFilename string `short:"F" long:"format" description:"File, to be formatted result file"` // 待格式化文件名
}

type OutputOption struct {
	Filename        string `short:"f" long:"file" description:"String, output filename"`
	FilePath        string `long:"path" description:"String, output file path"`
	Outputf         string `short:"o" long:"output" default:"default" description:"String,cmdline output format, default: full"`
	FileOutputf     string `short:"O" long:"file-output" default:"default" description:"String, file output format, default: jsonlines"` // 输出格式
	OutputDelimiter string `long:"output-delimiter" default:"\t" description:"String, output delimiter, default [TAB]"`
	AutoFile        bool   `long:"af" description:"Bool, auto choice filename"`        // 自动生成格式化文件名
	HiddenFile      bool   `long:"hf" description:"Bool, auto choice hidden filename"` // 启用自动隐藏文件
	Compress        bool   `short:"C" long:"compress" description:"Bool, close compress output file"`
	Tee             bool   `long:"tee" description:"Bool, keep console output"`          // 是否开启命令行输出扫描结果
	Quiet           bool   `short:"q" long:"quiet" description:"Bool, close log output"` // 是否开启命令行输出日志
	NoGuess         bool   `long:"no-guess" description:"Bool, When formatting not output guess framework"`
}

type SmartOption struct {
	Mod       string `short:"m" long:"mod" choice:"s" choice:"ss" choice:"default" choice:"sc" default:"default" description:"String, smart mod"` // 扫描模式
	Ping      bool   `long:"ping" description:"Bool, alive pre-scan"`
	NoScan    bool   `short:"n" long:"no" description:"Bool, just smart scan, return before default scan task"`
	PortProbe string `long:"sp" default:"default" description:"String, smart-port-probe, smart mod default: 80, supersmart mod default: icmp"` // 启发式扫描预设探针
	IpProbe   string `long:"ipp"  default:"default" description:"String, IP-probe, default: 1,254"`
}

type AdvanceOption struct {
	PortSpray   bool     `short:"s" long:"spray" description:"Bool, enable port-first spray generator. if ports number > 500, auto enable"`
	NoSpray     bool     `long:"no-spray" description:"Bool, force to close spray"`
	ExploitName string   `short:"E" long:"exploit-name" description:"String, specify neutron template name"` // 指定漏扫poc名字
	ExploitFile string   `long:"ef" description:"String, load specified templates file "`                    // 指定漏扫文件
	Payloads    []string `long:"payload" description:"String, specify neutron payload"`
	AttackType  string   `long:"attack-type" description:"neutron attack types, sniper|clusterbomb|pitchfork" choice:"pitchfork" choice:"clusterbomb" choice:"sniper"`
	Extract     []string `long:"extract" description:"String, custom Extract regexp"`
	//SuffixStr   string   `long:"suffix" description:"String, url path"`
	Opsec         bool     `long:"opsec" description:"Bool, opsec mode"`
	Filters       []string `long:"filter" description:"String, filter formatting(-F) results "`
	OutputFilters []string `long:"output-filter" description:"String, Filter output while scanning"`
	ScanFilters   []string `long:"scan-filter" description:"String, Filter Scanning while scanning"`
}

type MiscOption struct {
	Key         string `short:"k" long:"key" description:"String, file encrypt key"`
	Ver         bool   `long:"version" description:"Bool, show version"`                                                                                   // 输出版本号
	Printer     string `short:"P" long:"print" choice:"port" choice:"workflow" choice:"neutron" choice:"extract" description:"String, show preset config"` // 输出特定的预设
	Debug       bool   `long:"debug" description:"Bool, show debug info"`
	PluginDebug bool   `long:"plugin-debug" description:"Bool, show plugin debug stack"`
	Proxy       string `long:"proxy" description:"String, socks5 proxy url, e.g. socks5://127.0.0.1:11111"`
	//Dump        bool   `long:"dump" description:"dump all packet"`
}

type ConfigOption struct {
	Exploit    bool   `short:"e" long:"exploit" description:"Bool, enable neutron exploit scan"`                                       // 启用漏洞扫描
	Verbose    []bool `short:"v" long:"verbose" description:"Bool, enable active finger scan"`                                         // version level1
	Threads    int    `short:"t" long:"thread" description:"Int, concurrent thread number,linux default: 4000, windows default: 1000"` // 线程数
	Delay      int    `short:"d" long:"timeout" default:"2" description:"Int, socket and http timeout"`
	HttpsDelay int    `short:"D" long:"ssl-timeout" default:"2" description:"Int, ssl and https timeout"`
}

type Options struct {
	AliveSum    int32
	NoScan      bool
	PluginDebug bool
}

var Opt = Options{
	AliveSum: 0,
	NoScan:   false,
}
