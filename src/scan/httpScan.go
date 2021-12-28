package scan

import (
	"getitle/src/utils"
	"net/http"
	"strconv"
	"strings"
)

var headers = http.Header{
	"User-Agent": []string{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4577.82 Safari/537.36"},
}

// -defalut
//socket进行对网站的连接
func socketHttp(target string, result *utils.Result) {
	//fmt.Println(ip)
	//socket tcp连接,超时时间
	var err error
	var ishttp = false
	var statuscode = ""
	result.Protocol = "tcp"
	conn, err := utils.TcpSocketConn(target, RunOpt.Delay)
	if err != nil {
		//fmt.Println(err)
		result.Error = err.Error()
		return
	}
	result.Open = true

	// 启发式扫描探测直接返回不需要后续处理
	if result.HttpStat == "s" {
		return
	}

	result.HttpStat = "tcp"

	//发送内容
	senddata := []byte("GET / HTTP/1.1\r\nHost: " + target + "\r\nConnection: Keep-Alive\r\n\r\n")
	data, err := utils.SocketSend(conn, senddata, 4096)
	if err != nil {
		result.Error = err.Error()
	}

	//获取状态码
	result.Content = string(data)
	ishttp, statuscode = utils.GetStatusCode(result.Content)
	if ishttp {
		result.HttpStat = statuscode
		result.Protocol = "http"
	}

	//所有30x,400,以及非http协议的开放端口都送到http包尝试获取更多信息
	if result.HttpStat == "400" || result.Protocol == "tcp" || strings.HasPrefix(result.HttpStat, "3") {
		//return SystemHttp(target, result)
		SystemHttp(target, result)
	}
	conn.Close()
	return

}

//使用封装好了http
func SystemHttp(target string, result *utils.Result) {
	var conn http.Client
	var delay int
	// 如果是400或者不可识别协议,则使用https
	var ishttps bool
	if result.HttpStat == "400" || result.Protocol == "tcp" {
		target = "https://" + target
		ishttps = true
	} else {
		target = "http://" + target
	}

	//如果是https或者30x跳转,则增加超时时间
	if ishttps || strings.HasPrefix(result.HttpStat, "3") {
		delay = RunOpt.Delay + RunOpt.HttpsDelay
	}
	conn = utils.HttpConn(delay)
	req, _ := http.NewRequest("GET", target, nil)
	req.Header = headers
	resp, err := conn.Do(req)

	//resp, err := conn.Get(target+"/servlet/bsh.servlet.BshServlet")
	if resp != nil && resp.TLS != nil {
		result.Protocol = "https"
		result.Host = strings.Join(resp.TLS.PeerCertificates[0].DNSNames, ",")
		//result.Host = utils.FilterCertDomain(resp.TLS.PeerCertificates[0].DNSNames)
	}
	if err != nil {
		result.Error = err.Error()
		return
	}
	result.Error = ""
	result.Protocol = resp.Request.URL.Scheme
	result.HttpStat = strconv.Itoa(resp.StatusCode)
	result.Content = string(utils.GetBody(resp))
	result.Httpresp = resp

	return
}
