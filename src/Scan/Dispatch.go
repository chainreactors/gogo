package Scan

import (
	"getitle/src/Utils"
	"time"
)


var alivesum, titlesum int

var Delay time.Duration

func Dispatch(ip string,port string,delay time.Duration) Utils.Result{
	var result *Utils.Result = new(Utils.Result)
	Delay = delay

	target := ip + ":" + port
	switch port {
	case "443","8443":
		result = SystemHttp(target,"400")
	case "445":
		result = MS17010Scan(ip)
	case "6379":
		result = RedisScan(target)

	default:
		result = SocketHttp(target)
	}

	result.ip = ip
	result.port = port
	return result
}
