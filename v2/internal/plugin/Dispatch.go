package plugin

import (
	"github.com/chainreactors/gogo/v2/pkg"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/parsers/iutils"
	"sync/atomic"
)

type RunnerOpts struct {
	Sum          int32
	Exploit      string
	VersionLevel int
	Delay        int
	HttpsDelay   int
	SuffixStr    string
	Debug        bool
}

var RunOpt RunnerOpts

func Dispatch(result *pkg.Result) {
	defer func() {
		if err := recover(); err != nil {
			logs.Log.Errorf("scan %s unexcept error, %v", result.GetTarget(), err)
		}
	}()
	atomic.AddInt32(&RunOpt.Sum, 1)
	if result.Port == "137" || result.Port == "nbt" {
		nbtScan(result)
		return
	} else if result.Port == "135" || result.Port == "wmi" {
		wmiScan(result)
		return
	} else if result.Port == "oxid" {
		oxidScan(result)
		return
	} else if result.Port == "icmp" || result.Port == "ping" {
		icmpScan(result)
		return
	} else if result.Port == "snmp" || result.Port == "161" {
		snmpScan(result)
		return
	} else if result.Port == "445" || result.Port == "smb" {
		smbScan(result)
		if RunOpt.Exploit == "ms17010" {
			ms17010Scan(result)
		} else if RunOpt.Exploit == "smbghost" || RunOpt.Exploit == "cve-2020-0796" {
			smbGhostScan(result)
		} else if RunOpt.Exploit == "auto" || RunOpt.Exploit == "smb" {
			ms17010Scan(result)
			smbGhostScan(result)
		}
		return
	} else {
		initScan(result)
	}

	if !result.Open || result.SmartProbe {
		// 启发式探针或端口未OPEN,则直接退出, 不进行后续扫描
		return
	}

	// 指纹识别, 会根据versionlevel自动选择合适的指纹
	fingerScan(result)

	//主动信息收集
	if RunOpt.VersionLevel > 0 && result.IsHttp {
		// favicon指纹只有-v大于0并且为http服务才启用
		if result.HttpHosts != nil {
			hostScan(result)
		}

		faviconScan(result)
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
		Nuclei(result.GetHostBaseURL(), result)
	}

	result.Title = iutils.AsciiEncode(result.Title)
	return
}
