package engine

import (
	"bytes"
	"fmt"
	"github.com/chainreactors/gogo/v2/pkg"
	"github.com/chainreactors/logs"
	"strings"
)

// -default
// socket进行对网站的连接
func InitScan(result *pkg.Result) {
	var bs []byte
	target := result.GetTarget()
	defer func() {
		// 如果进行了各种探测依旧为tcp协议, 则收集tcp端口状态
		if result.Protocol == "tcp" {
			if result.Err != nil {
				result.Error = result.Err.Error()
				if RunOpt.Debug {
					result.ErrStat = handleError(result.Err)
				}
			}
		}
	}()

	conn, err := pkg.NewSocket("tcp", target, RunOpt.Delay)
	if err != nil {
		result.Err = err
		return
	}
	defer conn.Close()
	result.Open = true

	// 启发式扫描探测直接返回不需要后续处理
	if result.SmartProbe {
		return
	}
	result.Status = "open"

	bs, err = conn.Read(RunOpt.Delay)
	if err != nil {
		senddataStr := fmt.Sprintf("GET /%s HTTP/1.1\r\nHost: %s\r\n\r\n", result.Uri, target)
		bs, err = conn.Request([]byte(senddataStr), pkg.DefaultMaxSize)
		if err != nil {
			result.Err = err
		}
	}
	pkg.CollectSocketResponse(result, bs)

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
	conn := result.GetHttpConn(RunOpt.Delay + RunOpt.HttpsDelay)
	resp, err := pkg.HTTPGet(conn, target)
	if err != nil {
		// 有可能存在漏网之鱼, 是tls服务, 但tls的第一个响应为30x, 并30x的目的地址不可达或超时. 则会报错.
		result.Error = err.Error()
		logs.Log.Debugf("request %s , %s ", target, err.Error())
		if result.IsHttp {
			noRedirectHttp(result, target)
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

		pkg.CollectTLS(result, resp)
	} else if resp.Request.Response != nil && resp.Request.Response.TLS != nil {
		// 一种相对罕见的情况, 从https页面30x跳转到http页面. 则判断tls
		result.Protocol = "https"

		pkg.CollectTLS(result, resp.Request.Response)
	} else {
		result.Protocol = "http"
	}

	result.Error = ""
	pkg.CollectHttpResponse(result, resp)
	return
}

// 302跳转后目的不可达时进行不redirect的信息收集
// 暂时使用不太优雅的方案, 在极少数情况下才会触发, 会多进行一次https的交互.
func noRedirectHttp(result *pkg.Result, u string) {
	conn := pkg.HttpConnWithNoRedirect(RunOpt.Delay + RunOpt.HttpsDelay)
	resp, err := pkg.HTTPGet(conn, u)
	if err != nil {
		return
	}
	if err != nil {
		// 有可能存在漏网之鱼, 是tls服务, 但tls的第一个响应为30x, 并30x的目的地址不可达或超时. 则会报错.
		result.Error = err.Error()
		logs.Log.Debugf("request (no redirect) %s , %s ", u, err.Error())
		return
	}

	logs.Log.Debugf("request (no redirect) %s , %d ", u, resp.StatusCode)
	if resp.TLS != nil {
		if result.Status == "400" {
			result.Protocol = "https"
		}

		pkg.CollectTLS(result, resp)
	} else {
		result.Protocol = "http"
	}

	result.Error = ""
	pkg.CollectHttpResponse(result, resp)
}

func handleError(err error) int {
	errMsg := err.Error()
	if strings.Contains(errMsg, "refused") {
		return 1
	} else if strings.Contains(errMsg, "timeout") {
		return 2
	} else if strings.Contains(errMsg, "no route to host") {
		return 3
	} else if strings.Contains(errMsg, "permission denied") {
		return 4
	} else if strings.Contains(errMsg, "host is down") {
		return 5
	} else if strings.Contains(errMsg, "no such host") {
		return 6
	} else if strings.Contains(errMsg, "network is unreachable") {
		return 6
	} else if strings.Contains(errMsg, "The requested address is not valid in its context.") {
		return 6
	} else if strings.Contains(errMsg, "WSAECONNRESET") {
		return 8
	} else {
		return -1
	}
}
