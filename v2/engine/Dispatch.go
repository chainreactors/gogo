package engine

import (
	"sync/atomic"

	"github.com/chainreactors/gogo/v2/pkg"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/utils"
	"github.com/chainreactors/utils/iutils"
)

type RunnerOpts struct {
	Sum          int32
	Exploit      string
	VersionLevel int
	Delay        int
	HttpsDelay   int
	ScanFilters  [][]string
	//SuffixStr    string
	Debug        bool
	Opsec        bool // enable opsec
	ExcludeCIDRs utils.CIDRs
}

var (
	RunOpt RunnerOpts
)

func Dispatch(result *pkg.Result) {
	defer func() {
		if err := recover(); err != nil {
			logs.Log.Errorf("scan %s unexcept error, %v", result.GetTarget(), err)
			panic(err)
		}
	}()
	atomic.AddInt32(&RunOpt.Sum, 1)
	if RunOpt.ExcludeCIDRs != nil && RunOpt.ExcludeCIDRs.ContainsString(result.Ip) {
		logs.Log.Debug("exclude ip: " + result.Ip)
		return
	}
	if result.Port == "137" || result.Port == "nbt" {
		NBTScan(result)
		return
	} else if result.Port == "135" || result.Port == "wmi" {
		WMIScan(result)
		return
	} else if result.Port == "oxid" {
		OXIDScan(result)
		return
	} else if result.Port == "icmp" || result.Port == "ping" {
		ICMPScan(result)
		return
	} else if result.Port == "snmp" || result.Port == "161" {
		SNMPScan(result)
		return
	} else if result.Port == "445" || result.Port == "smb" {
		SMBScan(result)
		if RunOpt.Exploit == "ms17010" {
			MS17010Scan(result)
		} else if RunOpt.Exploit == "smbghost" || RunOpt.Exploit == "cve-2020-0796" {
			SMBGhostScan(result)
		} else if RunOpt.Exploit == "auto" || RunOpt.Exploit == "smb" {
			MS17010Scan(result)
			SMBGhostScan(result)
		}
		return
	} else if result.Port == "mssqlntlm" {
		MSSqlScan(result)
		return
	} else if result.Port == "winrm" {
		WinrmScan(result)
		return
	} else {
		InitScan(result)
	}

	if !result.Open || result.SmartProbe {
		// 启发式探针或端口未OPEN,则直接退出, 不进行后续扫描
		return
	}

	// 指纹识别, 会根据versionlevel自动选择合适的指纹
	if result.IsHttp {
		HTTPFingerScan(result)
	} else {
		SocketFingerScan(result)
	}

	if result.Filter(RunOpt.ScanFilters) {
		// 如果被过滤, 则停止后续扫描深度扫描
		return
	}
	//主动信息收集
	if RunOpt.VersionLevel > 0 && result.IsHttp {
		// favicon指纹只有-v大于0并且为http服务才启用
		if result.HttpHosts != nil {
			hostScan(result)
		}

		FaviconScan(result)
		if result.Status != "404" {
			NotFoundScan(result)
		}
	} else {
		// 如果versionlevel为0 ,或者非http服务, 则使用默认端口猜测指纹.
		if !result.IsHttp && result.NoFramework() {
			// 通过默认端口号猜测服务,不具备准确性
			result.GuessFramework()
		}
	}

	// 如果exploit参数不为none,则进行漏洞探测
	if RunOpt.Exploit != "none" {
		NeutronScan(result.GetHostBaseURL(), result)
	}

	result.Title = iutils.AsciiEncode(result.Title)
	return
}
