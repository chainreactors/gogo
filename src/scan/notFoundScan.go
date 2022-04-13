package scan

import (
	"getitle/src/fingers"
	"getitle/src/pkg"
	"getitle/src/utils"
)

func NotFoundScan(result *pkg.Result) {
	conn := result.GetHttpConn(RunOpt.Delay)

	resp, err := conn.Get(result.GetURL() + pkg.RandomDir)

	if err != nil {
		pkg.Log.Debugf("request 404page %s %s", result.GetURL()+pkg.RandomDir, err.Error())
		return
	}
	pkg.Log.Debugf("request 404page %s %d", result.GetURL()+pkg.RandomDir, resp.StatusCode)
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
