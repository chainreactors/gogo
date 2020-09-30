package http

import (
	"fmt"
	"net"
	"regexp"
	"time"
)

var sum int

func MyHttpSocket(ip string) string {
	//fmt.Println(ip)

	conn, err := net.DialTimeout("tcp", ip, 2*time.Second)

	if err != nil {

		//fmt.Println(err)
		return ""
	}

	_, err = conn.Write([]byte("GET / HTTP/1.1\r\nHost: " + ip + "\r\n\r\n"))

	if err != nil {
		return ""
	}

	err = conn.SetReadDeadline(time.Now().Add(time.Second))

	if err != nil {
		return ""
	}

	reply := make([]byte, 8192)
	_, err = conn.Read(reply)

	if err != nil {
		return ""
	}

	err = conn.Close()
	if err != nil {
		return ""
	}
	html := string(reply)

	r, _ := regexp.Compile("<title>(.*)</title>")

	res := r.FindStringSubmatch(html)

	if len(res) < 2 {
		result := "[+]" + ip + "  open ---------"
		//fmt.Println(result)
		sum++
		return result
	}

	result := "[+]" + ip + "  open ---------" + res[1]

	sum++
	return result

}

func OutputSum() {
	fmt.Println(sum)
}
