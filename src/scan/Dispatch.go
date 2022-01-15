package scan

import (
	"getitle/src/utils"
	"strings"
)

type RunnerOpts struct {
	Sum          int
	Exploit      string
	VersionLevel int
	Delay        int
	HttpsDelay   int
	Payloadstr   string
}

var RunOpt = RunnerOpts{
	Sum: 0,
}

func Dispatch(result *utils.Result) {
	target := result.GetTarget()
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
	} else if result.Port == "icmp" {
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
		socketHttp(target, result)
	}

	// 启发式扫描探测直接返回不需要后续处理
	if result.HttpStat == "s" {
		return
	}

	if result.Open {

		//被动收集基本信息
		result.InfoFilter()
		fingerScan(result)
		// 指定payload扫描
		if result.IsHttp() && RunOpt.Payloadstr != "" {
			payloadScan(result)
			return
		}

		//主动信息收集
		// 因为正则匹配耗时较长,如果没有-v参数则字节不进行服务识别
		if RunOpt.VersionLevel >= 1 && strings.HasPrefix(result.Protocol, "http") {
			faviconScan(result)
		} else {
			if !result.IsHttp() && result.NoFramework() {
				// 通过默认端口号猜测服务,不具备准确性
				result.GuessFramework()
			}
		}

		// 如果-e参数为true,则进行漏洞探测
		if RunOpt.Exploit != "none" {
			ExploitDispatch(result)
		}

		result.Title = utils.EncodeTitle(result.Title)
		return
	}

}

func ExploitDispatch(result *utils.Result) {
	//if strings.Contains(result.Content, "-ERR wrong") {
	//	RedisScan(target, result)
	//}
	if (!result.NoFramework() || RunOpt.Exploit != "auto") && result.IsHttp() {
		Nuclei(result.GetURL(), result)
	}

	if RunOpt.Exploit != "auto" { // 如果exploit值不为auto,则不进行shiro和ms17010扫描
		return
	}
	// todo 将shiro改造成nuclei poc
	if result.IsHttp() {
		shiroScan(result)
	}

	//if result.Port == "11211" {
	//	MemcacheScan(target, result)
	//}
	return
}
