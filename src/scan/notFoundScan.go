package scan

import (
	"getitle/src/utils"
)

//
//import (
//	"main/src/utils"
//	"io/ioutil"
//	"strings"
//)
//
func NotFoundScan(result *utils.Result) {
	conn := utils.HttpConn(2)
	resp, err := conn.Get(result.GetURL() + utils.RandomDir)
	if err != nil {
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
