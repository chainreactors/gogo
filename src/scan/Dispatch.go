package scan

import (
	"getitle/src/utils"
	"strings"
)

var Sum int
var Exploit string
var VersionLevel int
var Delay int
var HttpsDelay int
var Payloadstr string

func Dispatch(result *utils.Result) {
	target := result.GetTarget()
	Sum++
	//println(result.Ip)
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
		snmpScan(result.Ip, result)
		return
	} else if result.Port == "445" || result.Port == "smb" {
		smbScan(result)
		if Exploit == "ms17010" {
			ms17010Scan(result)
		} else if Exploit == "smbghost" || Exploit == "cve-2020-0796" {
			smbGhostScan(result)
		} else if Exploit == "auto" || Exploit == "smb" {
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
		if result.IsHttp() && Payloadstr != "" {
			payloadScan(result)
			return
		}

		//主动信息收集
		// 因为正则匹配耗时较长,如果没有-v参数则字节不进行服务识别
		if VersionLevel == 1 {
			if result.NoFramework() && strings.HasPrefix(result.Protocol, "http") {
				faviconScan(result)
			}
		} else if VersionLevel == 2 {
			faviconScan(result)
		} else {
			if !result.IsHttp() && result.NoFramework() {
				// 通过默认端口号猜测服务,不具备准确性
				result.GuessFramework()
			}
		}

		// 如果-e参数为true,则进行漏洞探测
		if Exploit != "none" {
			ExploitDispatch(result)
		}

		// 输出前处理
		if (result.TcpCon) != nil {
			(*result.TcpCon).Close()
		}
		result.Title = strings.TrimSpace(result.Title)
		result.Title = strings.Trim(result.Title, "\x00")

		return
	}

}

func ExploitDispatch(result *utils.Result) {
	//if strings.Contains(result.Content, "-ERR wrong") {
	//	RedisScan(target, result)
	//}
	if (!result.NoFramework() || Exploit != "auto") && result.IsHttp() {
		Nuclei(result.GetURL(), result)
	}

	if Exploit != "auto" { // 如果exploit值不为auto,则不进行shiro和ms17010扫描
		return
	}
	if result.IsHttp() {
		shiroScan(result)
	}

	//if result.Port == "11211" {
	//	MemcacheScan(target, result)
	//}
	return
}
