package plugin

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"

	"github.com/chainreactors/gogo/v2/pkg"
	"github.com/chainreactors/logs"
)

var headers = http.Header{
	"User-Agent": []string{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"},
}

// -default
// socket进行对网站的连接
func initScan(result *pkg.Result) {
	var bs []byte
	target := result.GetTarget()
	if pkg.ProxyUrl != nil && strings.HasPrefix(pkg.ProxyUrl.Scheme, "http") {
		// 如果是http代理, 则使用http库代替socket
		conn := result.GetHttpConn(RunOpt.Delay)
		req, _ := http.NewRequest("GET", "http://"+target, nil)
		resp, err := conn.Do(req)
		if err != nil {
			result.Error = err.Error()
			return
		}
		result.Open = true
		pkg.CollectHttpResponse(result, resp)
	} else {
		conn, err := pkg.NewSocket("tcp", target, RunOpt.Delay)
		//conn, err := pkg.TcpSocketConn(target, RunOpt.Delay)
		if err != nil {
			// return open: 0, closed: 1, filtered: 2, noroute: 3, denied: 4, down: 5, error_host: 6, unkown: -1
			errMsg := err.Error()
			result.Error = errMsg
			if RunOpt.Debug {
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
			}
			return
		}
		defer conn.Close()
		result.Open = true

		// 启发式扫描探测直接返回不需要后续处理
		if result.SmartProbe {
			return
		}
		result.Status = "tcp"

		bs, err = conn.Read(1) // 已经建立了连接, timeout不用过长时间, 如果没有返回值就可以直接进入下一步
		if err != nil {
			senddataStr := fmt.Sprintf("GET /%s HTTP/1.1\r\nHost: %s\r\n\r\n", result.Uri, target)
			bs, err = conn.Request([]byte(senddataStr), 4096)
			if err != nil {
				result.Error = err.Error()
			}
		}
		pkg.CollectSocketResponse(result, bs)
	}

	//所有30x,400,以及非http协议的开放端口都送到http包尝试获取更多信息
	if result.Status == "400" || result.Protocol == "tcp" || (strings.HasPrefix(result.Status, "3") && bytes.Contains(result.Content, []byte("location: https"))) {
		systemHttp(result, "https")
	} else if strings.HasPrefix(result.Status, "3") {
		systemHttp(result, "http")
	}
	return
}

// 使用net/http进行带redirect的请求
func systemHttp(result *pkg.Result, scheme string) {

	// 如果是400或者不可识别协议,则使用https
	target := scheme + "://" + result.GetTarget()

	//if RunOpt.SuffixStr != "" {
	//	target += "/" + RunOpt.SuffixStr
	//}

	conn := result.GetHttpConn(RunOpt.Delay + RunOpt.HttpsDelay)
	req, _ := http.NewRequest("GET", target, nil)
	req.Header = headers

	resp, err := conn.Do(req)
	if err != nil {
		// 有可能存在漏网之鱼, 是tls服务, 但tls的第一个响应为30x, 并30x的目的地址不可达或超时. 则会报错.
		result.Error = err.Error()
		logs.Log.Debugf("request %s , %s ", target, err.Error())
		if result.IsHttp {
			noRedirectHttp(result, req)
		}
		return
	}
	logs.Log.Debugf("request %s , %d ", target, resp.StatusCode)
	if resp.TLS != nil {
		if result.Status == "400" {
			// socket中得到的状态为400, 且存在tls的情况下
			result.Protocol = "https"
		} else if resp.StatusCode == 400 {
			// 虽然获取到了tls, 但是状态码为400, 则根据scheme取反
			// 某些中间件会自动打开tls端口, 但是证书为空, 返回400
			if scheme == "http" {
				result.Protocol = "https"
			} else {
				result.Protocol = "http"
			}
		} else if scheme == "http" && resp.Request.Response != nil && resp.Request.URL.Scheme == "https" {
			// 去掉通过302 http跳转到https导致可能存在的误判
			result.Protocol = "http"
		} else {
			result.Protocol = scheme
		}

		collectTLS(result, resp)
	} else if resp.Request.Response != nil && resp.Request.Response.TLS != nil {
		// 一种相对罕见的情况, 从https页面30x跳转到http页面. 则判断tls
		result.Protocol = "https"

		collectTLS(result, resp.Request.Response)
	} else {
		result.Protocol = "http"
	}

	result.Error = ""
	pkg.CollectHttpResponse(result, resp)
	return
}

// 302跳转后目的不可达时进行不redirect的信息收集
// 暂时使用不太优雅的方案, 在极少数情况下才会触发, 会多进行一次https的交互.
func noRedirectHttp(result *pkg.Result, req *http.Request) {
	conn := pkg.HttpConnWithNoRedirect(RunOpt.Delay + RunOpt.HttpsDelay)
	req.Header = headers
	resp, err := conn.Do(req)
	if err != nil {
		// 有可能存在漏网之鱼, 是tls服务, 但tls的第一个响应为30x, 并30x的目的地址不可达或超时. 则会报错.
		result.Error = err.Error()
		logs.Log.Debugf("request (no redirect) %s , %s ", req.URL.String(), err.Error())
		return
	}

	logs.Log.Debugf("request (no redirect) %s , %d ", req.URL.String(), resp.StatusCode)
	if resp.TLS != nil {
		if result.Status == "400" {
			result.Protocol = "https"
		}

		collectTLS(result, resp)
	} else {
		result.Protocol = "http"
	}

	result.Error = ""
	pkg.CollectHttpResponse(result, resp)
}

func collectTLS(result *pkg.Result, resp *http.Response) {
	result.Host = strings.Join(resp.TLS.PeerCertificates[0].DNSNames, ",")
	if len(resp.TLS.PeerCertificates[0].DNSNames) > 0 {
		// 经验公式: 通常只有cdn会绑定超过2个host, 正常情况只有一个host或者带上www的两个host
		result.HttpHosts = append(result.HttpHosts, pkg.FormatCertDomains(resp.TLS.PeerCertificates[0].DNSNames)...)
	}
}
