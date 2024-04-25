package plugin

import (
	"github.com/chainreactors/fingers/common"
	. "github.com/chainreactors/gogo/v2/pkg"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/parsers"
	"strings"
)

func httpFingerScan(result *Result) {
	passiveHttpMatch(result)
	if RunOpt.VersionLevel > 0 {
		activeHttpMatch(result)
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

func activeHttpMatch(result *Result) {
	var closureResp *parsers.Response
	var finalResp *parsers.Response
	sender := func(sendData []byte) ([]byte, bool) {
		conn := result.GetHttpConn(RunOpt.Delay)
		url := result.GetURL() + string(sendData)
		logs.Log.Debugf("active detect: %s", url)
		resp, err := conn.Get(url)
		if err == nil {
			return parsers.ReadRaw(resp), true
		} else {
			return nil, false
		}
	}

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
		} else {
			if closureResp != nil {
				fs, vs := historyMatch(closureResp)
				if len(fs) > 0 {
					i += result.Frameworks.Merge(fs)
					result.Vulns.Merge(vs)
				}
			}
		}

		if i > 0 {
			n += i
			finalResp = closureResp
		}
	}

	FingerEngine.HTTPActiveMatch(RunOpt.VersionLevel, sender, callback)

	if finalResp != nil {
		// 如果匹配到新的指纹, 重新收集基本信息
		CollectParsedResponse(result, finalResp)
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
