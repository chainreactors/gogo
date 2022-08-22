package plugin

import (
	"fmt"
	"github.com/chainreactors/gogo/v1/pkg"
	"github.com/chainreactors/logs"
	"net/http"
	"strings"
)

var headers = http.Header{
	"User-Agent": []string{"Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0;"},
}

// -default
//socket进行对网站的连接
func initScan(result *pkg.Result) {
	var bs []byte
	target := result.GetTarget()
	if pkg.Proxy != nil && pkg.ProxyUrl.Scheme == "socks5" {
		conn, err := pkg.NewSocket("tcp", target, RunOpt.Delay)
		//conn, err := pkg.TcpSocketConn(target, RunOpt.Delay)
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
		//var host string
		//if result.CurrentHost == "" {
		//	host = target
		//} else {
		//	host = fmt.Sprintf("%s:%s", result.CurrentHost, result.Port)
		//}

		bs, err = conn.Read(1)
		//buf := make([]byte, 4096)
		//_ = conn.SetReadDeadline(time.Now().Add(time.Duration(500) * time.Millisecond))
		//n, err := conn.Read(buf)
		if err != nil {
			senddataStr := fmt.Sprintf("GET /%s HTTP/1.1\r\nHost: %s\r\nConnection: Keep-Alive\r\n\r\n", result.Uri, target)
			bs, err = conn.Request([]byte(senddataStr), 4096)
			if err != nil {
				result.Error = err.Error()
			}
		}
		//获取状态码
		result.Content = strings.ToLower(string(bs))
		pkg.CollectSocketInfo(result, bs)
	} else {
		conn := result.GetHttpConn(RunOpt.Delay)
		req, _ := http.NewRequest("GET", "http://"+target, nil)
		resp, err := conn.Do(req)
		if err != nil {
			result.Error = err.Error()
			return
		}
		result.Open = true
		content := pkg.GetHttpRaw(resp)
		result.Content = strings.ToLower(content)
		pkg.CollectHttpInfo(result, resp, content)
	}

	//所有30x,400,以及非http协议的开放端口都送到http包尝试获取更多信息
	if result.HttpStat == "400" || result.Protocol == "tcp" || strings.HasPrefix(result.HttpStat, "3") {
		//return systemHttp(target, result)
		systemHttp(result)
	}
	return
}

//使用封装好了http
func systemHttp(result *pkg.Result) {
	var delay int
	// 如果是400或者不可识别协议,则使用https
	var ishttps bool
	target := result.GetTarget()
	if result.HttpStat == "400" || result.Protocol == "tcp" {
		target = "https://" + target
		ishttps = true
	} else {
		target = "http://" + target
	}

	if RunOpt.SuffixStr != "" {
		target += "/" + RunOpt.SuffixStr
	}
	//如果是https或者30x跳转,则增加超时时间
	if ishttps || strings.HasPrefix(result.HttpStat, "3") {
		delay = RunOpt.Delay + RunOpt.HttpsDelay
	}
	conn := result.GetHttpConn(delay)
	req, _ := http.NewRequest("GET", target, nil)
	req.Header = headers
	//if result.CurrentHost != "" {
	//	req.Host = result.CurrentHost
	//}

	resp, err := conn.Do(req)
	if err != nil {
		result.Error = err.Error()
		logs.Log.Debugf("request %s , %s ", target, err.Error())
		return
	}
	logs.Log.Debugf("request %s , %d ", target, resp.StatusCode)

	if resp.TLS != nil {
		// 证书在错误处理之前, 因为有可能存在证书,但是服务已关闭
		result.Protocol = "https"
		result.Cert = strings.Join(resp.TLS.PeerCertificates[0].DNSNames, ",")
		if len(resp.TLS.PeerCertificates[0].DNSNames) > 0 && len(resp.TLS.PeerCertificates[0].DNSNames) < 3 && result.HttpHosts == nil {
			// 经验公式: 通常只有cdn会绑定超过2个host, 正常情况只有一个host或者带上www的两个host
			result.HttpHosts = append(result.HttpHosts, pkg.FormatCertDomains(resp.TLS.PeerCertificates[0].DNSNames)...)
		}
	}

	result.Error = ""
	content := pkg.GetHttpRaw(resp)
	result.Content = strings.ToLower(content)
	pkg.CollectHttpInfo(result, resp, content)
	return
}
