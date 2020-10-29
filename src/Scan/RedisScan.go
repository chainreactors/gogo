package Scan

import (
	"net"
	"strings"
	"time"
	"getitle/src/Utils"
)

func RedisScan(target string)map[string]string  {
	var result map[string]string
	result = make(map[string]string)
	conn, err := net.DialTimeout("tcp", target, Delay* time.Second)
	if err != nil {

		//fmt.Println(err)
		result["stat"] = "CLOSE"
		return result
	}
	result["stat"] = "OPEN"
	recv := Utils.SocketSend(conn,[]byte("info"))
	if strings.Contains(string(recv),"redis_version") {
		result["framework"] =  Utils.Match("redis_version:",string(recv))
	}
	return result
}
