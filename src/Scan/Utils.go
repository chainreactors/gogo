package Scan

import (
	"net"
	"strings"
)


func SocketSend(conn net.Conn, data []byte) []byte {
	//发送内容
	var err error
	_, err = conn.Write(data)
	if err != nil {
		return []byte{0x00}
	}

	//最多只读8192位,一般来说有title就肯定已经有了
	reply := make([]byte, 2048)
	_, err = conn.Read(reply)

	if err != nil {
		return []byte{0x00}
	}
	return reply
}

func Encode(s string)string {
	s = strings.Replace(s,"\r","%13",-1)
	s = strings.Replace(s,"\n","%10",-1)
	return s
}