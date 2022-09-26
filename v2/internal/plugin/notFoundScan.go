package plugin

import (
	"github.com/chainreactors/gogo/v2/pkg"
	"github.com/chainreactors/gogo/v2/pkg/fingers"
	"github.com/chainreactors/gogo/v2/pkg/utils"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/parsers"
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
	if utils.ToString(resp.StatusCode) == result.Status {
		return
	}
	content := string(parsers.ReadRaw(resp))
	if content == "" {
		return
	}

	for _, finger := range pkg.AllFingers {
		framework, _, ok := fingers.FingerMatcher(finger, strings.ToLower(content), 0, nil)
		if ok {
			framework.From = fingers.NOTFOUND
			result.AddFramework(framework)
		}
	}
}
