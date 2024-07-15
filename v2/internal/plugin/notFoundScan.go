package plugin

import (
	"github.com/chainreactors/fingers/fingers"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/utils/httputils"

	"github.com/chainreactors/gogo/v2/pkg"
	"github.com/chainreactors/utils/iutils"
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
	content := httputils.ReadRaw(resp)
	if len(content) == 0 {
		return
	}

	fs, _ := pkg.FingerEngine.HTTPMatch(content, "")
	for _, frame := range fs {
		frame.From = fingers.NOTFOUND
		result.AddFramework(frame)
	}
}
