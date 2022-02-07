package scan

import (
	"getitle/src/pkg"
	"getitle/src/structutils"
)

func NotFoundScan(result *pkg.Result) {
	conn := pkg.HttpConn(RunOpt.Delay)
	resp, err := conn.Get(result.GetURL() + pkg.RandomDir)
	if err != nil || structutils.ToString(resp.StatusCode) == result.HttpStat {
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
