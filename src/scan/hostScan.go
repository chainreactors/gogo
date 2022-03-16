package scan

import (
	"getitle/src/pkg"
	"net/http"
	"strings"
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

	if resp.StatusCode != 200 {
		return
	}
	content, body := pkg.GetHttpRaw(resp)
	hash := pkg.Md5Hash([]byte(strings.TrimSpace(body)))[:4] // 因为头中经常有随机值, 因此hash通过body判断
	if result.Hash != hash {
		pkg.CollectHttpInfo(result, resp, content, body)
		result.AddVuln(&pkg.Vuln{Name: "host", Payload: map[string]interface{}{"hostname": result.HttpHost}, Severity: "info"})
	}
}
