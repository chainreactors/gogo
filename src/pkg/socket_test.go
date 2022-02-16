package pkg

import (
	"fmt"
	"net"
	"testing"
)

func TestName(t *testing.T) {
	conn, err := net.Dial("tcp", "10.40.106.1:1234")
	if err != nil {
		fmt.Printf(err.Error())
	}
	fmt.Print(conn)
	//_ = conn.SetDeadline(time.Now().Add(delay * time.Second))
}
