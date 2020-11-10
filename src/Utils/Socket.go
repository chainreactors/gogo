package Utils

import (
	"crypto/tls"
	"net"
	"net/http"
	"time"
)

func TcpSocketConn(target string, Delay time.Duration) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", target, Delay*time.Second)

	if err != nil {
		return nil, err
	}
	err = conn.SetDeadline(time.Now().Add(Delay * time.Second))
	return conn, err
}

func UdpSocketConn(target string, Delay time.Duration) (net.Conn, error) {

	conn, err := net.DialTimeout("udp", target, Delay*time.Second)

	if err != nil {
		return nil, err
	}
	err = conn.SetDeadline(time.Now().Add(Delay * time.Second))
	return conn, err
}

func SocketSend(conn net.Conn, data []byte, length int) (int, []byte, error) {

	var err error
	_, err = conn.Write(data)
	if err != nil {
		return 0, []byte{0x00}, err
	}

	//最多只读8192位,一般来说有title就肯定已经有了
	reply := make([]byte, length)
	n, err := conn.Read(reply)

	if err != nil {
		return n, []byte{0x00}, err
	}
	return n, reply, err
}

func GetTarget(ip string, port string) string {
	return ip + ":" + port
}

func HttpConn(delay time.Duration) http.Client {
	tr := &http.Transport{
		//TLSHandshakeTimeout : delay * time.Second,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	conn := &http.Client{
		Transport: tr,
		Timeout:   delay * time.Second,
	}
	return *conn
}
