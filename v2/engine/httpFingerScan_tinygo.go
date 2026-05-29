//go:build tinygo
// +build tinygo

package engine

import (
	"net/http"
	"strings"

	"github.com/chainreactors/fingers/common"
	. "github.com/chainreactors/gogo/v2/pkg"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/parsers"
)

type GogoRoundTripper struct {
	result *Result
	opt    *RunnerOption
}

func (g *GogoRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	conn := g.result.GetHttpConnWithOpt(g.opt.Delay, g.opt)
	logs.Log.Debugf("Active detect: %s %s", req.Method, req.URL.String())

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
	transport := &GogoRoundTripper{
		result: result,
		opt:    opt,
	}

	baseURL := result.GetURL()
	callback := func(f *common.Framework, v *common.Vuln) {
		if f != nil {
			result.Frameworks.Add(f)
			if v != nil {
				result.Vulns.Add(v)
			}
		}
	}

	FingerEngine.HTTPActiveMatch(baseURL, 2, transport, callback)

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
