package Scan

import (
	"getitle/src/Utils"
	"strings"
)

func RedisScan(target string, result Utils.Result) Utils.Result {

	conn, err := Utils.TcpSocketConn(target, Delay)
	if err != nil {

		//fmt.Println(err)
		result.Error = err.Error()
		return result
	}
	result.Stat = "OPEN"
	result.Protocol = "redis"
	_, recv, _ := Utils.SocketSend(conn, []byte("info"), 2048)
	if strings.Contains(string(recv), "redis_version") {
		result.Title = Utils.Match("redis_version:(.*)", string(recv))
	}
	return result
}
