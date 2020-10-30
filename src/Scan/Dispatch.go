package Scan

import (
	"getitle/src/Utils"
	"time"
)

var Alivesum, Titlesum int

var Delay time.Duration

func Dispatch(result Utils.Result) Utils.Result {
	target := Utils.GetTarget(result.Ip, result.Port)
	switch result.Port {
	case "443", "8443":
		result = SystemHttp(target, result, "400")
	case "445":
		result = MS17010Scan(target, result)
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
	}
	//if result.Title != "" {
	//	Titlesum ++
	//}
	return result
}
