package Scan

import (
	"getitle/src/Utils"
	"strconv"
	"strings"
)

//socket进行对网站的连接
func SocketHttp(target string, result Utils.Result) Utils.Result {
	//fmt.Println(ip)
	//socket tcp连接,超时时间
	result.Protocol = "http"
	conn, err := Utils.TcpSocketConn(target, Delay)
	if err != nil {
		//fmt.Println(err)
		result.Error = err.Error()
		return result
	}
	result.Stat = "OPEN"

	//发送内容
	senddata := []byte("GET / HTTP/1.1\r\nHost: " + target + "\r\n\r\n")
	_, data, _ := Utils.SocketSend(conn, senddata, 4096)
	content := string(data)
	err = conn.Close()
	if err != nil {
		result.Error = err.Error()
		return result
	}

	//获取状态码
	result.Content = content
	result.HttpStat = Utils.GetStatusCode(content)
	//如果是400可能是因为没有用https
	if result.HttpStat == "400" || strings.HasPrefix(result.HttpStat, "3") {
		result = SystemHttp(target, result)
	}

	//正则匹配title

	return Utils.InfoFilter(content, result)

}

//使用封装好了http
func SystemHttp(target string, result Utils.Result) Utils.Result {
	if result.HttpStat == "400" || result.Port == "443" || result.Port == "8443" || result.Port == "4443" {
		target = "https://" + target
		result.Protocol = "https"
	} else {
		target = "http://" + target
		result.Protocol = "http"
	}
	conn := Utils.HttpConn(Delay)

	resp, err := conn.Get(target)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	result.Stat = "OPEN"
	result.HttpStat = strconv.Itoa(resp.StatusCode)

	//result.Content

	_ = resp.Body.Close()

	result.Content = Utils.GetHttpRaw(*resp)

	return Utils.InfoFilter(result.Content, result)
}
