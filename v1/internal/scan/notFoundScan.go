package scan

import (
	"getitle/src/pkg"
	"getitle/src/pkg/fingers"
	"getitle/src/pkg/utils"
)

func NotFoundScan(result *pkg.Result) {
	conn := result.GetHttpConn(RunOpt.Delay)
	url := result.GetURL() + pkg.RandomDir
	resp, err := conn.Get(url)

	if err != nil {
		pkg.Log.Debugf("request 404page %s %s", url, err.Error())
		return
	}
	pkg.Log.Debugf("request 404page %s %d", url, resp.StatusCode)
	if utils.ToString(resp.StatusCode) == result.HttpStat {
		return
	}
	content := string(pkg.GetBody(resp))
	if content == "" {
		return
	}

	for _, finger := range pkg.AllFingers {
		framework, _, ok := fingers.FingerMatcher(finger, content)
		if ok {
			framework.Version = "404"
			result.AddFramework(framework)
		}
	}
}
