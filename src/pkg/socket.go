package pkg

import (
	"net"
	"time"
)

func NewSocket(target string, delay int, t string) Socket {
	s := Socket{}
	var conn net.Conn
	if t == "tcp" {
		conn, _ = net.DialTimeout("tcp", target, time.Duration(delay)*time.Second)
	} else if t == "udp" {
		conn, _ = net.DialTimeout("udp", target, time.Duration(delay)*time.Second)
	} else {
		return s
	}
	s.Conn = conn
	return s
}

type Socket struct {
	Conn  net.Conn
	Count int
}

func (s *Socket) Request(data []byte, max int) ([]byte, error) {
	_ = s.Conn.SetDeadline(time.Now().Add(time.Duration(2) * time.Second))
	var err error
	_, err = s.Conn.Write(data)
	if err != nil {
		return []byte{}, err
	}
	s.Count++
	buf := make([]byte, max)
	time.Sleep(time.Duration(200) * time.Millisecond)
	n, err := s.Conn.Read(buf)
	if err != nil {
		return []byte{}, err
	}
	return buf[:n], err
}

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
	time.Sleep(time.Duration(200) * time.Millisecond)
	n, err := conn.Read(buf)
	if err != nil {
		return []byte{}, err
	}
	return buf[:n], err
}
