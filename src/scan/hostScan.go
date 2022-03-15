package scan

import (
	"getitle/src/pkg"
	"net/http"
)

func hostScan(result *pkg.Result) {
	url := result.GetURL()
	conn := pkg.HttpConn(RunOpt.Delay)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Host", result.HttpHost)
	resp, err := conn.Do(req)
	if err != nil {
		return
	}

	if resp.StatusCode == 200 {
		content, body := pkg.GetHttpRaw(resp)
		pkg.CollectHttpInfo(result, resp, content, body)
	}
}
