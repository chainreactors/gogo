package pkg

import (
	"net"
	"time"
)

func NewSocket(network, target string, delay int) (*Socket, error) {
	s := &Socket{
		Timeout: time.Duration(delay) * time.Second,
	}
	var conn net.Conn
	var err error
	if ProxyDialTimeout != nil {
		conn, err = ProxyDialTimeout(network, target, s.Timeout)
	} else {
		conn, err = net.DialTimeout(network, target, s.Timeout)
	}
	if err != nil {
		return nil, err
	}

	s.Conn = conn
	return s, nil
}

type Socket struct {
	Conn    net.Conn
	Count   int
	Timeout time.Duration
}

func (s *Socket) Read(timeout int) ([]byte, error) {
	buf := make([]byte, 16384)
	s.Conn.SetReadDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
	n, err := s.Conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func (s *Socket) Request(data []byte, max int) ([]byte, error) {
	_ = s.Conn.SetDeadline(time.Now().Add(s.Timeout))
	var err error
	_, err = s.Conn.Write(data)
	if err != nil {
		return []byte{}, err
	}
	s.Count++
	buf := make([]byte, max)
	time.Sleep(time.Duration(500) * time.Millisecond)
	n, err := s.Conn.Read(buf)
	if err != nil {
		return []byte{}, err
	}
	return buf[:n], err
}

func (s *Socket) QuickRequest(data []byte, max int) ([]byte, error) {
	_ = s.Conn.SetDeadline(time.Now().Add(s.Timeout))
	var err error
	_, err = s.Conn.Write(data)
	if err != nil {
		return []byte{}, err
	}
	s.Count++
	buf := make([]byte, max)
	n, err := s.Conn.Read(buf)
	if err != nil {
		return []byte{}, err
	}
	return buf[:n], err
}

func (s *Socket) Close() {
	s.Conn.Close()
}

var ProxyDialTimeout func(network, address string, timeout time.Duration) (net.Conn, error)
