package Utils

import "net"

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

