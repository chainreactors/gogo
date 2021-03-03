package Utils

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"
)

func TcpSocketConn(target string, delay time.Duration) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", target, delay*time.Second)
	if err != nil {
		return nil, err
	}
	//_ = conn.SetDeadline(time.Now().Add(delay * time.Second))
	return conn, err
}

func UdpSocketConn(target string, delay time.Duration) (net.Conn, error) {

	conn, err := net.DialTimeout("udp", target, delay*time.Second)

	if err != nil {
		return nil, err
	}
	err = conn.SetDeadline(time.Now().Add(delay * time.Second))
	return conn, err
}

func SocketSend(conn net.Conn, data []byte, length int) (int, []byte, error) {
	_ = conn.SetDeadline(time.Now().Add(time.Duration(2) * time.Second))
	var err error
	_, err = conn.Write(data)
	if err != nil {
		return 0, []byte{}, err
	}

	//最多只读8192位,一般来说有title就肯定已经有了
	reply := make([]byte, length)
	n, err := conn.Read(reply)

	if err != nil {
		return n, []byte{}, err
	}
	return n, reply, err
}

func TcpIsClose(conn net.Conn) {

}

func HttpIsClose(conn http.Client) {

}

func GetTarget(result *Result) string {
	return fmt.Sprintf("%s:%s", result.Ip, result.Port)
}

func GetURL(result *Result) string {
	return fmt.Sprintf("%s://%s:%s", result.Protocol, result.Ip, result.Port)
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
