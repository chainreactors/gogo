package engine

import (
	"net/http"
	"strings"

	"github.com/chainreactors/fingers/common"
	. "github.com/chainreactors/gogo/v2/pkg"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/parsers"
)

// GogoRoundTripper 实现 http.RoundTripper 接口
// 使用 gogo 的 HTTP 客户端发送请求
type GogoRoundTripper struct {
	result *Result
	opt    *RunnerOption
}

// RoundTrip 实现 http.RoundTripper 接口
func (g *GogoRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// 获取连接
	conn := g.result.GetHttpConn(g.opt.Delay)

	// 使用原始请求，保留所有 headers、method、body 等信息
	logs.Log.Debugf("Active detect: %s %s", req.Method, req.URL.String())

	// 直接使用 conn.Do 发送原始请求
	httpResp, err := conn.Do(req)
	if err != nil {
		logs.Log.Debugf("Request failed: %v", err)
		return nil, err
	}

	return httpResp, nil
}

func HTTPFingerScan(opt *RunnerOption, result *Result) {
	passiveHttpMatch(result)
	if opt.VersionLevel > 0 {
		activeHttpMatch(opt, result)

	}
	return
}

func passiveHttpMatch(result *Result) {
	fs, vs := FingerEngine.HTTPMatch(result.Content, strings.Join(result.HttpHosts, ","))
	if len(fs) > 0 {
		result.AddVulnsAndFrameworks(fs, vs)
	}

	fs, vs = historyMatch(result.Httpresp)
	if len(fs) > 0 {
		result.AddVulnsAndFrameworks(fs, vs)
	}
}

func activeHttpMatch(opt *RunnerOption, result *Result) {
	var closureResp *http.Response
	var finalResp *http.Response

	// 创建统一的 GogoRoundTripper，两个引擎共用
	transport := &GogoRoundTripper{
		result: result,
		opt:    opt,
	}

	baseURL := result.GetURL()

	// FingerEngine 使用统一的 http.RoundTripper
	var n int
	callback := func(f *common.Framework, v *common.Vuln) {
		var i int
		if f != nil {
			ok := result.Frameworks.Add(f)
			if ok {
				i += 1
			}
			if v != nil {
				result.Vulns.Add(v)
			}
		}

		if i > 0 {
			n += i
			finalResp = closureResp
		}
	}

	FingerEngine.HTTPActiveMatch(baseURL, 2, transport, callback)

	// FingerprintHub active matching - 使用同一个 http.RoundTripper
	if opt.VersionLevel >= 2 && FingerprintHubEngine != nil {
		fphCallback := func(f *common.Framework, v *common.Vuln) {
			if f != nil {
				result.Frameworks.Add(f)
			}
			if v != nil {
				result.Vulns.Add(v)
			}
		}

		fs, vs := FingerprintHubEngine.HTTPActiveMatch(baseURL, opt.VersionLevel, transport, fphCallback)
		if len(fs) > 0 {
			result.AddFrameworks(fs.List())
		}
		if len(vs) > 0 {
			result.AddVulns(vs.List())
		}
	}

	if finalResp != nil {
		// TODO: CollectParsedResponse needs parsers.Response, but finalResp is now http.Response
		// Need to investigate the correct HTTP client to use
		// CollectParsedResponse(result, finalResp)
	}
}

func historyMatch(resp *parsers.Response) (common.Frameworks, common.Vulns) {
	if resp.History == nil {
		return nil, nil
	}
	fs := make(common.Frameworks)
	vs := make(common.Vulns)
	for _, content := range resp.History {
		f, v := FingerEngine.HTTPMatch(content.Raw, "")
		fs.Merge(f)
		vs.Merge(v)
	}
	return fs, vs
}
