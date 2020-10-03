package http

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"time"
)

var alivesum, titlesum int

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
		alivesum++
		return result
	}

	result := "[+]" + ip + "  open ---------" + res[1]

	alivesum++
	titlesum++

	return result

}

func SystemHttp(ip string) string {

	ip = "http://" + ip

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	c := &http.Client{
		Transport: tr,
		Timeout:   2 * time.Second,
	}
	resp, err := c.Get(ip)

	if err != nil {
		return ""
	}

	reply, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()

	html := string(reply)

	if err != nil {

		return ""
	}

	r, _ := regexp.Compile("<title>(.*)</title>")

	res := r.FindStringSubmatch(html)

	if len(res) < 2 {
		result := "[+]" + ip + "  open ---------"
		//fmt.Println(result)
		alivesum++
		return result
	}

	result := "[+]" + ip + "  open ---------" + res[1]

	alivesum++
	titlesum++

	return result
}

func OutputAliveSum() {
	fmt.Println("AliveSum: " + strconv.Itoa(alivesum))
}

func OutputTitleSum() {
	fmt.Println("TitleSum: " + strconv.Itoa(titlesum))
}
