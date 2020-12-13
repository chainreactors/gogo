package Scan

import (
	"getitle/src/Utils"
	"strings"
	"time"
)

var Alivesum, Sum int
var Exploit bool
var Delay time.Duration

func Dispatch(result Utils.Result) Utils.Result {
	target := Utils.GetTarget(result.Ip, result.Port)
	Sum++
	//println(result.ip,result.Port)
	switch result.Port {
	case "137":
		result = NbtScan(target, result)
	case "135":
		result = OXIDScan(target, result)
	case "445":
		result = MS17010Scan(target, result)
	case "icmp":
		result = IcmpScan(target, result)

	default:
		result = SocketHttp(target, result)
	}

	// 如果端口开放-e参数为true,则尝试进行漏洞探测
	if result.Stat == "OPEN" {
		Alivesum++
		result = Utils.InfoFilter(result)
		// 如果-e参数为true,则进行漏洞探测
		if Exploit {
			result = ExploitDispatch(result)
		}
	}

	//if result.Title != "" {
	//	Titlesum ++
	//}
	result.Content = ""
	return result
}

func ExploitDispatch(result Utils.Result) Utils.Result {

	//
	target := Utils.GetTarget(result.Ip, result.Port)
	if strings.Contains(result.Content, "-ERR wrong") {
		result = RedisScan(target, result)
	}
	if strings.HasPrefix(result.Protocol, "http") {
		result = ShiroScan(target, result)
	}
	if result.Port == "445" {
		result = MS17010Scan(target, result)
	}
	return result
}
