package scan

import (
	"getitle/src/pkg"
	"getitle/src/utils"
)

func NotFoundScan(result *pkg.Result) {
	conn := pkg.HttpConn(RunOpt.Delay)
	pkg.Log.Debug("request 404page " + result.GetURL() + pkg.RandomDir)
	resp, err := conn.Get(result.GetURL() + pkg.RandomDir)
	if err != nil || utils.ToString(resp.StatusCode) == result.HttpStat {
		return
	}
	content := string(pkg.GetBody(resp))
	if content == "" {
		return
	}

	for _, finger := range pkg.AllFingers {
		framework, ok := fingerMatcher(result, finger, content)
		if ok {
			framework.Version = "404"
			result.AddFramework(framework)
		}
	}
}
