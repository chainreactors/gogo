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

	_, recv, _ := Utils.SocketSend(conn, []byte("info"), 2048)
	if strings.Contains(string(recv), "redis_version") {
		result.Protocol = "redis"
		result.Title = Utils.Match("redis_version:(.*)", string(recv))
		result.Vuln = "redis Unauth"
	}
	return result
}
