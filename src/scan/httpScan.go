package scan

import (
	"getitle/src/pkg"
	"getitle/src/utils"
	"net/http"
	"strings"
)

var headers = http.Header{
	"User-Agent": []string{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4577.82 Safari/537.36"},
}

// -defalut
//socket进行对网站的连接
func socketHttp(target string, result *pkg.Result) {
	//fmt.Println(ip)
	//socket tcp连接,超时时间
	var err error
	var ishttp = false
	var statuscode = ""
	result.Protocol = "tcp"
	conn, err := pkg.TcpSocketConn(target, RunOpt.Delay)
	if err != nil {
		// return open: 0, closed: 1, filtered: 2, noroute: 3, denied: 4, down: 5, error_host: 6, unkown: -1
		errMsg := err.Error()
		result.Error = errMsg
		if strings.Contains(errMsg, "refused") {
			result.ErrStat = 1
		} else if strings.Contains(errMsg, "timeout") {
			result.ErrStat = 2
		} else if strings.Contains(errMsg, "no route to host") {
			result.ErrStat = 3
		} else if strings.Contains(errMsg, "permission denied") {
			result.ErrStat = 4
		} else if strings.Contains(errMsg, "host is down") {
			result.ErrStat = 5
		} else if strings.Contains(errMsg, "no such host") {
			result.ErrStat = 6
		} else if strings.Contains(errMsg, "network is unreachable") {
			result.ErrStat = 6
		} else if strings.Contains(errMsg, "The requested address is not valid in its context.") {
			result.ErrStat = 6
		} else {
			result.ErrStat = -1
		}
		return
	}
	defer conn.Close()
	result.Open = true

	// 启发式扫描探测直接返回不需要后续处理
	if result.SmartProbe {
		return
	}

	result.HttpStat = "tcp"

	//发送内容
	senddata := []byte("GET / HTTP/1.1\r\nHost: " + target + "\r\nConnection: Keep-Alive\r\n\r\n")
	data, err := pkg.SocketSend(conn, senddata, 4096)
	if err != nil {
		result.Error = err.Error()
	}

	//获取状态码
	result.Content = string(data)
	ishttp, statuscode = pkg.GetStatusCode(result.Content)
	if ishttp {
		result.HttpStat = statuscode
		result.Protocol = "http"
	}

	//所有30x,400,以及非http协议的开放端口都送到http包尝试获取更多信息
	if result.HttpStat == "400" || result.Protocol == "tcp" || strings.HasPrefix(result.HttpStat, "3") {
		//return SystemHttp(target, result)
		SystemHttp(target, result)
	}
	return

}

//使用封装好了http
func SystemHttp(target string, result *pkg.Result) {
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
	conn = pkg.HttpConn(delay)
	req, _ := http.NewRequest("GET", target, nil)
	req.Header = headers
	resp, err := conn.Do(req)
	if resp != nil && resp.TLS != nil {
		// 证书在错误处理之前, 因为有可能存在证书,但是服务已关闭
		result.Protocol = "https"
		result.Host = strings.Join(resp.TLS.PeerCertificates[0].DNSNames, ",")
	}
	if err != nil {
		result.Error = err.Error()
		return
	}
	result.Error = ""
	result.Protocol = resp.Request.URL.Scheme
	result.HttpStat = utils.ToString(resp.StatusCode)
	result.Content, result.Body = pkg.GetHttpRaw(resp)
	result.Httpresp = resp

	return
}
