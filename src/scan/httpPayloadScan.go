package scan

import (
	"getitle/src/utils"
	"strconv"
)

func payloadScan(result *utils.Result) {
	url := result.GetURL()
	//println(url+Payloadstr)
	result.Uri = Payloadstr
	conn := utils.HttpConn(Delay)
	resp, err := conn.Get(url + Payloadstr)
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
