package Scan

import (
	"strings"
	"time"
)


var alivesum, titlesum int

var Delay time.Duration

func Dispatch(target string,delay time.Duration) string{
	var tmp []string
	var result string
	Delay = delay
	tmp = strings.Split(target, ":")
	switch tmp[1] {
	case "443","8443":
		result = SystemHttp(target,"400")
	case "445":
		result = MS17010Scan(tmp[0])
	default:
		result = SocketHttp(target)
	}
	return result
}
