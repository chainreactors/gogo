package Scan

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
	"getitle/src/Utils"
)

var Outp string

//socket进行对网站的连接
func SocketHttp(target string) Utils.Result {
	//fmt.Println(ip)
	var result *Utils.Result = new(Utils.Result)
	//socket tcp连接,超时时间
	conn, err := net.DialTimeout("tcp", target, Delay* time.Second)
	if err != nil {

		//fmt.Println(err)
		result.Stat = "CLOSE"
		result.Error = err.Error()
		return *result
	}
	result.Stat = "OPEN"
	alivesum++
	err = conn.SetReadDeadline(time.Now().Add(Delay * time.Second))


	//发送内容
	data :=[]byte("GET / HTTP/1.1\r\nHost: " + target + "\r\n\r\n")
	content := string(Utils.SocketSend(conn,data))
	err = conn.Close()
	if err != nil {
		result.Error = err.Error()
		return *result
	}

	//获取状态码
	status := GetStatusCode(content)

	//如果是400可能是因为没有用https
	if status == "400" || strings.HasPrefix(status,"3") {
		result = SystemHttp(target,status)
		return *result
	}

	//正则匹配title


	return Utils.InfoFilter(content,"http")


}

//使用封装好了http
func SystemHttp(target string,status string) Utils.Result  {
	var result *Utils.Result = new(Utils.Result)

	var protocol string
	if status == "400" {
		target = "https://" + target
		protocol = "https"
	} else{
		target = "http://" + target
		protocol = "http"
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	c := &http.Client{
		Transport: tr,
		Timeout:   Delay * time.Second,
	}

	resp, err := c.Get(target)
	if err != nil {
		result.Stat = "CLOSE"
		result.Error = err.Error()
		return  *result
	}
	result.Stat = "OPEN"

	alivesum++
	reply, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()

	content := string(reply)

	if err != nil {

		result.Error = err.Error()
		return  *result

	}

	return Utils.InfoFilter(content,protocol)
}

func GetStatusCode(html string) string {
	http1 := strings.Split(html, "\n")[0]
	statusC := strings.Split(http1, " ")
	if len(statusC) > 2 {
		statusCode := statusC[1]
		return statusCode
	}

	return ""
}

func OutputAliveSum() {
	fmt.Println("AliveSum: " + strconv.Itoa(alivesum))
}

func OutputTitleSum() {
	fmt.Println("TitleSum: " + strconv.Itoa(titlesum))
}



