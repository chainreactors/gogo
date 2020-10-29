package Scan

import (
	"crypto/tls"
	"getitle/src/Utils"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

//socket进行对网站的连接
func SocketHttp(target string, result Utils.Result) Utils.Result {
	//fmt.Println(ip)
	//socket tcp连接,超时时间

	conn, err := Utils.SocketConn(target, Delay)
	if err != nil {
		//fmt.Println(err)
		result.Stat = "CLOSE"
		result.Error = err.Error()
		return result
	}
	result.Stat = "OPEN"
	result.Protocol = "http"

	//发送内容
	data := []byte("GET / HTTP/1.1\r\nHost: " + target + "\r\n\r\n")
	content := string(Utils.SocketSend(conn, data))
	err = conn.Close()
	if err != nil {
		result.Error = err.Error()
		return result
	}

	//获取状态码
	status := GetStatusCode(content)

	//如果是400可能是因为没有用https
	if status == "400" || strings.HasPrefix(status, "3") {
		return SystemHttp(target, result, status)
	}
	if strings.Contains(content, "-ERR wrong") {
		result = RedisScan(target, result)
	}

	//正则匹配title

	return Utils.InfoFilter(content, result)

}

//使用封装好了http
func SystemHttp(target string, result Utils.Result, status string) Utils.Result {

	if status == "400" {
		target = "https://" + target
		result.Protocol = "https"
	} else {
		target = "http://" + target
		result.Protocol = "http"
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	conn := &http.Client{
		Transport: tr,
		Timeout:   Delay * time.Second,
	}

	resp, err := conn.Get(target)
	if err != nil {
		result.Stat = "CLOSE"
		result.Error = err.Error()
		return result
	}
	result.Stat = "OPEN"

	reply, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()

	content := string(reply)

	if err != nil {

		result.Error = err.Error()
		return result

	}

	return Utils.InfoFilter(content, result)
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


