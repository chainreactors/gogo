package Scan

import (
	"getitle/src/Utils"
	"net"
	"strings"
	"time"
)

func RedisScan(target string, result Utils.Result) Utils.Result {

	conn, err := net.DialTimeout("tcp", target, Delay*time.Second)
	if err != nil {

		//fmt.Println(err)
		result.Stat = "CLOSE"
		return result
	}
	result.Stat = "OPEN"
	result.Protocol = "redis"
	recv := Utils.SocketSend(conn, []byte("info"))
	if strings.Contains(string(recv), "redis_version") {
		result.Title = Utils.Match("redis_version:(.*)", string(recv))
	}
	return result
}
