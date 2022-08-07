package scan

import (
	"getitle/v1/pkg"
	"getitle/v1/pkg/fingers"
	"getitle/v1/pkg/utils"
	"github.com/chainreactors/logs"
	"strings"
)

func NotFoundScan(result *pkg.Result) {
	conn := result.GetHttpConn(RunOpt.Delay)
	url := result.GetURL() + pkg.RandomDir
	resp, err := conn.Get(url)

	if err != nil {
		logs.Log.Debugf("request 404page %s %s", url, err.Error())
		return
	}

	logs.Log.Debugf("request 404page %s %d", url, resp.StatusCode)
	if utils.ToString(resp.StatusCode) == result.HttpStat {
		return
	}
	content := pkg.GetHttpRaw(resp)
	if content == "" {
		return
	}

	for _, finger := range pkg.AllFingers {
		framework, _, ok := fingers.FingerMatcher(finger, 0, strings.ToLower(content), nil)
		if ok {
			framework.From = "404"
			result.AddFramework(framework)
		}
	}
}
