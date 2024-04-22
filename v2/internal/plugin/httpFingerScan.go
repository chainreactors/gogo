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
	sender := func(sendData []byte) ([]byte, bool) {
		conn := result.GetHttpConn(RunOpt.Delay)
		url := result.GetURL() + string(sendData)
		logs.Log.Debugf("active detect: %s", url)
		resp, err := conn.Get(url)
		if err == nil {
			closureResp = parsers.NewResponse(resp)
			return parsers.ReadRaw(resp), true
		} else {
			return nil, false
		}
	}
	var n int
	fs, vs := FingerEngine.HTTPActiveMatch(RunOpt.VersionLevel, sender)
	if len(fs) > 0 {
		n = result.Frameworks.Merge(fs)
		result.Vulns.Merge(vs)
	} else {
		if closureResp != nil {
			fs, vs = historyMatch(closureResp)
			if len(fs) > 0 {
				n += result.Frameworks.Merge(fs)
				result.Vulns.Merge(vs)
			}
		}
	}

	if n > 0 {
		// 如果匹配到新的指纹, 重新收集基本信息
		CollectParsedResponse(result, closureResp)
	}
}

func historyMatch(resp *parsers.Response) (common.Frameworks, common.Vulns) {
	fs := make(common.Frameworks)
	vs := make(common.Vulns)
	for _, content := range resp.History {
		f, v := FingerEngine.HTTPMatch(content.Raw, "")
		fs.Merge(f)
		vs.Merge(v)
	}
	return fs, vs
}
