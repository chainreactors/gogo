package scan

import (
	"getitle/src/structutils"
	"getitle/src/utils"
)

func NotFoundScan(result *utils.Result) {
	conn := utils.HttpConn(RunOpt.Delay)
	resp, err := conn.Get(result.GetURL() + utils.RandomDir)
	if err != nil || structutils.ToString(resp.StatusCode) == result.HttpStat {
		return
	}
	content := string(utils.GetBody(resp))
	if content == "" {
		return
	}

	for _, finger := range utils.AllFingers {
		framework, ok := fingerMatcher(result, finger, content)
		if ok {
			framework.Version = "404"
			result.AddFramework(framework)
		}
	}
}
