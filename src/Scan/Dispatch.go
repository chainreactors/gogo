package Scan

import (
	"getitle/src/Utils"
	"strings"
	"time"
)

var Alivesum, Sum int
var Exploit bool
var Version bool
var Delay time.Duration

func Dispatch(result *Utils.Result) {
	target := Utils.GetTarget(result)
	Sum++
	//println(result.Ip, result.Port)
	switch result.Port {
	case "137":
		NbtScan(target, result)
		return
	case "135":
		OXIDScan(target, result)
		return
	case "icmp":
		IcmpScan(result.Ip, result)
		return
	default:
		SocketHttp(target, result)
	}

	if result.Stat == "OPEN" {
		Alivesum++

		//被动收集基本信息
		Utils.InfoFilter(result)

		// 因为正则匹配耗时较长,如果没有-v参数则字节不进行服务识别
		if Version {
			Utils.GetDetail(result)
			if result.Framework == "" && strings.HasPrefix(result.Protocol, "http") {
				FaviconScan(result)
			}
		}
		// 如果-e参数为true,则进行漏洞探测
		if Exploit {
			ExploitDispatch(result)
		}
	}

	//if result.Title != "" {
	//	Titlesum ++
	//}
	if (result.TcpCon) != nil {
		(*result.TcpCon).Close()
	}
	result.Title = strings.TrimSpace(result.Title)
	return

}

func ExploitDispatch(result *Utils.Result) {

	//
	target := Utils.GetTarget(result)
	if strings.Contains(result.Content, "-ERR wrong") {
		RedisScan(target, result)
	}
	if strings.HasPrefix(result.Protocol, "http") {
		ShiroScan(result)
	}
	if result.Port == "445" {
		MS17010Scan(target, result)
	}
	if result.Port == "11211" {
		MemcacheScan(target, result)
	}
	return
}
