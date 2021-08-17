package utils

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"
)

func TcpSocketConn(target string, delay int) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", target, time.Duration(delay)*time.Second)
	if err != nil {
		return nil, err
	}
	//_ = conn.SetDeadline(time.Now().Add(delay * time.Second))
	return conn, err
}

func UdpSocketConn(target string, delay int) (net.Conn, error) {

	conn, err := net.DialTimeout("udp", target, time.Duration(delay)*time.Second)
	if err != nil {
		return nil, err
	}
	//err = conn.SetDeadline(time.Now().Add(delay * time.Second))
	return conn, err
}

func SocketSend(conn net.Conn, data []byte, max int) ([]byte, error) {
	_ = conn.SetDeadline(time.Now().Add(time.Duration(2) * time.Second))
	var err error
	_, err = conn.Write(data)
	if err != nil {
		return []byte{}, err
	}

	buf := make([]byte, max)
	time.Sleep(time.Duration(100) * time.Millisecond)
	_, err = conn.Read(buf)
	if err != nil {
		return bytes.Trim(buf, "\x00"), err
	}
	return bytes.Trim(buf, "\x00"), err
}

func GetTarget(result *Result) string {
	return fmt.Sprintf("%s:%s", result.Ip, result.Port)
}

func GetURL(result *Result) string {
	return fmt.Sprintf("%s://%s:%s", result.Protocol, result.Ip, result.Port)
}

func HttpConn(delay int) http.Client {
	tr := &http.Transport{
		//TLSHandshakeTimeout : delay * time.Second,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	conn := &http.Client{
		Transport: tr,
		Timeout:   time.Duration(delay) * time.Second,
	}
	return *conn
}
