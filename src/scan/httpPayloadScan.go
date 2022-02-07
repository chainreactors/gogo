package scan

import (
	"getitle/src/pkg"
	"strconv"
)

func payloadScan(result *pkg.Result) {
	url := result.GetURL()
	//println(url+Payloadstr)
	result.Uri = RunOpt.Payloadstr
	conn := pkg.HttpConn(RunOpt.Delay)
	resp, err := conn.Get(url + RunOpt.Payloadstr)
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
