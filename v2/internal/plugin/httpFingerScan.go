package plugin

import (
	. "github.com/chainreactors/gogo/v2/pkg"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/parsers"
	"net/http"
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

	historyMatch(result, result.Httpresp)
}

func activeHttpMatch(result *Result) {
	var closureResp *http.Response
	sender := func(sendData []byte) ([]byte, bool) {
		conn := result.GetHttpConn(RunOpt.Delay)
		url := result.GetURL() + string(sendData)
		logs.Log.Debugf("active detect: %s", url)
		resp, err := conn.Get(url)
		if err == nil {
			closureResp = resp
			return parsers.ReadRaw(resp), true
		} else {
			return nil, false
		}
	}

	fs, vs := FingerEngine.HTTPActiveMatch(RunOpt.VersionLevel, sender)
	if len(fs) > 0 {
		result.AddVulnsAndFrameworks(fs, vs)
	}
	resp := parsers.NewResponse(closureResp)
	historyMatch(result, resp)
}

func historyMatch(result *Result, resp *parsers.Response) {
	for _, content := range resp.History {
		fs, vs := FingerEngine.HTTPMatch(content.Raw, "")
		result.AddVulnsAndFrameworks(fs, vs)
	}
}
