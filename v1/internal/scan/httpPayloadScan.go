package scan

import (
	"getitle/src/pkg"
	"strconv"
)

func suffixScan(result *pkg.Result) {
	url := result.GetBaseURL()
	//println(url+SuffixStr)
	result.Uri = RunOpt.SuffixStr
	conn := result.GetHttpConn(RunOpt.Delay)
	resp, err := conn.Get(url + RunOpt.SuffixStr)
	if err != nil {
		result.Error = err.Error()
		return
	}
	result.Protocol = resp.Request.URL.Scheme
	result.HttpStat = strconv.Itoa(resp.StatusCode)
	result.Content = string(pkg.GetBody(resp))
	result.Httpresp = resp

	return
}
