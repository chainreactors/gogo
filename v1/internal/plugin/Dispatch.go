package plugin

import (
	"github.com/chainreactors/gogo/pkg"
	"net"
)

type RunnerOpts struct {
	Sum          int
	Exploit      string
	VersionLevel int
	Delay        int
	HttpsDelay   int
	SuffixStr    string
	Interface    *net.Interface
}

var RunOpt = RunnerOpts{
	Sum: 0,
}

func Dispatch(result *pkg.Result) {
	RunOpt.Sum++
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
	} else if result.Port == "arp" && !pkg.Win {
		arpScan(result)
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

	// 指定payload扫描
	//	根据指定的payload进行探测, 探测完后即结束
	//if result.IsHttp() && RunOpt.SuffixStr != "" {
	//suffixScan(result)
	//return
	//}

	//主动信息收集
	if RunOpt.VersionLevel > 0 && result.IsHttp() {
		// favicon指纹只有-v大于0并且为http服务才启用
		if result.HttpHosts != nil {
			hostScan(result)
		}

		faviconScan(result)
		if result.HttpStat != "404" {
			NotFoundScan(result)
		}
	} else {
		// 如果versionlevel为0 ,或者非http服务, 则使用默认端口猜测指纹.
		if !result.IsHttp() && result.NoFramework() {
			// 通过默认端口号猜测服务,不具备准确性
			result.GuessFramework()
		}
	}

	// 如果exploit参数不为none,则进行漏洞探测
	if RunOpt.Exploit != "none" {
		ExploitDispatch(result)
	}

	//if result.IsHttp() && result.Host == "" {
	//	result.Host = result.CurrentHost
	//}

	if result.Httpresp != nil && !result.Httpresp.Close {
		_ = result.Httpresp.Body.Close()
	}
	return
}

func ExploitDispatch(result *pkg.Result) {
	if result.IsHttp() && (RunOpt.Exploit == "auto" || RunOpt.Exploit == "shiro") {
		// todo 将shiro改造成nuclei poc
		shiroScan(result)
	}

	if (!result.NoFramework() || RunOpt.Exploit != "auto") && result.IsHttp() {
		Nuclei(result.GetHostBaseURL(), result)
	}

	return
}
