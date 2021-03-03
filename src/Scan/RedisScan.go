package Scan

import (
	"getitle/src/Utils"
	"strings"
)

// -e
func RedisScan(target string, result *Utils.Result) {
	result.Framework = "redis"
	conn, err := Utils.TcpSocketConn(target, Delay)
	if err != nil {

		//fmt.Println(err)
		result.Error = err.Error()
		return
	}

	_, recv, _ := Utils.SocketSend(conn, []byte("info\n"), 1024)
	if strings.Contains(string(recv), "redis_version") {
		result.Protocol = "tcp"
		result.Title = "redis " + Utils.Match("redis_version:(.*)", string(recv))
		result.Vuln = "redis Unauth"
	}
	return
}
