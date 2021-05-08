package Scan

import (
	"getitle/src/Utils"
	"strconv"
)

func PayloadScan(result *Utils.Result) {
	url := Utils.GetURL(result)
	//println(url+Payloadstr)
	result.Uri = Payloadstr
	conn := Utils.HttpConn(Delay)
	resp, err := conn.Get(url + Payloadstr)
	if err != nil {
		result.Error = err.Error()
		return
	}
	result.Protocol = resp.Request.URL.Scheme
	result.HttpStat = strconv.Itoa(resp.StatusCode)
	result.Content = string(Utils.GetBody(resp))
	result.Httpresp = resp
	_ = resp.Body.Close()

	return
}
