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
	switch result.Port {
	case "443", "8443", "4443":
		result = SystemHttp(target, result)
	//case "445":
	//	result = MS17010Scan(target, result)
	case "137":
		result = NbtScan(target, result)
	case "135":
		result = OXIDScan(target, result)
	case "6379":
		result = RedisScan(target, result)

	default:
		result = SocketHttp(target, result)
	}

	if result.Stat == "OPEN" {
		Alivesum++
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
	if result.HttpStat == "200" || strings.HasPrefix(result.HttpStat, "3") {
		result = ShiroScan(target, result)
	}
	return result
}
