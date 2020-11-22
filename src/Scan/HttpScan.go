package Scan

import (
	"getitle/src/Utils"
	"net/http"
	"strconv"
	"strings"
	"time"
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

	//所有30x,400,以及非http协议的开放端口都送到http包尝试获取更多信息
	if result.HttpStat == "400" || result.HttpStat == "999" || strings.HasPrefix(result.HttpStat, "3") {
		return SystemHttp(target, result)
	}

	return Utils.InfoFilter(content, result)

}

//使用封装好了http
func SystemHttp(target string, result Utils.Result) Utils.Result {
	var conn http.Client
	var delay time.Duration
	// 如果是400或者不可识别协议,则使用https
	if result.HttpStat == "400" || result.HttpStat == "999" {
		target = "https://" + target
		result.Protocol = "https"
	} else {
		target = "http://" + target
		result.Protocol = "http"
	}

	//如果是https或者30x跳转,则增加超时时间
	if result.Protocol == "https" || strings.HasPrefix(result.HttpStat, "3") {
		delay = Delay + 2
	}
	conn = Utils.HttpConn(delay)
	resp, err := conn.Get(target)
	//resp, err := conn.Get(target+"/servlet/bsh.servlet.BshServlet")
	if resp != nil && resp.TLS != nil {
		result.Host = Utils.FilterCertDomain(resp.TLS.PeerCertificates[0].DNSNames)
	}
	if err != nil {
		result.Error = err.Error()
		return result
	}
	result.Stat = "OPEN"
	result.HttpStat = strconv.Itoa(resp.StatusCode)
	result.Content = Utils.GetHttpRaw(*resp)
	_ = resp.Body.Close()
	return Utils.InfoFilter(result.Content, result)
}
