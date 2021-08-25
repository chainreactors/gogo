package scan

import (
	"getitle/src/utils"
	"strings"
)

var Alivesum, Sum int
var Exploit string
var VersionLevel int
var Delay int
var HttpsDelay int
var Payloadstr string

func Dispatch(result *utils.Result) {
	target := result.GetTarget()
	Sum++
	//println(result.Ip)
	if result.Port == "137" {
		nbtScan(target, result)
		return
	} else if result.Port == "135" {
		oxidScan(target, result)
		return
	} else if result.Port == "icmp" {
		icmpScan(result.Ip, result)
		return
	} else if result.Port == "snmp" {
		snmpScan(result.Ip, result)
		return
	} else {
		socketHttp(target, result)
	}

	// 启发式扫描探测直接返回不需要后续处理
	if result.HttpStat == "s" {
		return
	}

	if result.Stat == "OPEN" {
		Alivesum++

		//被动收集基本信息
		result.InfoFilter()

		// 指定payload扫描
		if result.IsHttp() && Payloadstr != "" {
			payloadScan(result)
			return
		}

		//主动信息收集
		// 因为正则匹配耗时较长,如果没有-v参数则字节不进行服务识别
		fingerScan(result)
		if VersionLevel > 0 {
			if result.Framework == "" && strings.HasPrefix(result.Protocol, "http") {
				faviconScan(result)
			}
		}

		// 如果-e参数为true,则进行漏洞探测
		if Exploit != "noneaa" {
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
	//
	target := result.GetTarget()
	//if strings.Contains(result.Content, "-ERR wrong") {
	//	RedisScan(target, result)
	//}
	if (result.Framework != "" || Exploit != "auto") && result.IsHttp() {
		Nuclei(result.GetURL(), result)
	}

	if Exploit != "auto" { // 如果exploit值不为auto,则不进行shiro和ms17010扫描
		return
	}
	if result.IsHttp() {
		shiroScan(result)
	}
	if result.Port == "445" {
		ms17010Scan(target, result)
	}
	//if result.Port == "11211" {
	//	MemcacheScan(target, result)
	//}
	return
}
