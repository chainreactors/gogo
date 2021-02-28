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

func Dispatch(result Utils.Result) Utils.Result {
	target := Utils.GetTarget(result)
	Sum++
	//println(result.Ip, result.Port)
	switch result.Port {
	case "137":
		result = NbtScan(target, result)
	case "135":
		result = OXIDScan(target, result)
	case "icmp":
		result = IcmpScan(result.Ip, result)
	default:
		result = SocketHttp(target, result)
	}

	if result.Stat == "OPEN" {
		Alivesum++

		//被动收集基本信息
		result = Utils.InfoFilter(result)

		// 因为正则匹配耗时较长,如果没有-v参数则字节不进行服务识别
		if Version {
			result = Utils.GetDetail(result)
		}
		// 如果-e参数为true,则进行漏洞探测
		if Exploit {
			result = ExploitDispatch(result)
		}
	}

	//if result.Title != "" {
	//	Titlesum ++
	//}
	result.TcpCon.Close()
	result.Content = ""
	result.Title = strings.TrimSpace(result.Title)
	return result
}

func ExploitDispatch(result Utils.Result) Utils.Result {

	//
	target := Utils.GetTarget(result)
	if strings.Contains(result.Content, "-ERR wrong") {
		result = RedisScan(target, result)
	}
	if strings.HasPrefix(result.Protocol, "http") {
		result = ShiroScan(result)
	}
	if result.Port == "445" {
		result = MS17010Scan(target, result)
	}
	if result.Port == "11211" {
		result = MemcacheScan(target, result)
	}
	return result
}
