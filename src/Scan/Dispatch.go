package Scan

import (
	"getitle/src/Utils"
	"time"
)

var alivesum, titlesum int

var Delay time.Duration

func Dispatch(result Utils.Result, delay time.Duration) Utils.Result {
	Delay = delay
	target := result.Ip + ":" + result.Port
	switch result.Port {
	case "443", "8443":
		result = SystemHttp(target, result, "400")
	case "445":
		result = MS17010Scan(result.Ip, result)
	case "137":
		result = NbtScan(result.Ip, result)
	case "6379":
		result = RedisScan(target, result)

	default:
		result = SocketHttp(target, result)
	}

	return result
}
