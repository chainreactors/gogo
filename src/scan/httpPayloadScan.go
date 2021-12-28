package scan

import (
	"getitle/src/utils"
	"strconv"
)

func payloadScan(result *utils.Result) {
	url := result.GetURL()
	//println(url+Payloadstr)
	result.Uri = RunOpt.Payloadstr
	conn := utils.HttpConn(RunOpt.Delay)
	resp, err := conn.Get(url + RunOpt.Payloadstr)
	if err != nil {
		result.Error = err.Error()
		return
	}
	result.Protocol = resp.Request.URL.Scheme
	result.HttpStat = strconv.Itoa(resp.StatusCode)
	result.Content = string(utils.GetBody(resp))
	result.Httpresp = resp

	return
}
