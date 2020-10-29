package Utils

import (
	"net"
	"time"
)

func SocketConn(target string,Delay time.Duration)(net.Conn,error ) {
	conn, err := net.DialTimeout("tcp", target, Delay*time.Second)
	if err != nil {
		return nil, err
	}
	err = conn.SetDeadline(time.Now().Add(Delay * time.Second))
	return  conn,err
}


func SocketSend(conn net.Conn, data []byte) []byte {

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

