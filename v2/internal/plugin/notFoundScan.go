package plugin

import (
	"bytes"

	"github.com/chainreactors/gogo/v2/pkg"
	"github.com/chainreactors/gogo/v2/pkg/fingers"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/parsers"
	"github.com/chainreactors/parsers/iutils"
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
	if iutils.ToString(resp.StatusCode) == result.Status {
		return
	}
	content := parsers.ReadRaw(resp)
	if len(content) == 0 {
		return
	}

	for _, finger := range pkg.AllHttpFingers {
		framework, _, ok := fingers.FingerMatcher(finger, map[string]interface{}{"content": bytes.ToLower(content)}, 0, nil)
		if ok {
			framework.From = fingers.NOTFOUND
			result.AddFramework(framework)
		}
	}
}
