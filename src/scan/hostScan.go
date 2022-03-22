package scan

import (
	"getitle/src/pkg"
	"net/http"
	"strings"
)

func hostScan(result *pkg.Result) {
	url := result.GetBaseURL()
	conn := pkg.HttpConn(RunOpt.Delay)
	req, _ := http.NewRequest("GET", url, nil)
	vuln := &pkg.Vuln{Name: "host", Detail: map[string]interface{}{}, Severity: "info"}
	for _, host := range result.HttpHost {

		req.Host = host
		resp, err := conn.Do(req)
		if err != nil {
			return
		}

		if resp.StatusCode != 200 {
			continue
		}
		content, body := pkg.GetHttpRaw(resp)
		hash := pkg.Md5Hash([]byte(strings.TrimSpace(body)))[:4] // 因为头中经常有随机值, 因此hash通过body判断
		if result.Hash != hash {
			vuln.Detail[host] = pkg.AsciiEncode(pkg.GetTitle(content))
		}
	}
	if len(vuln.Detail) > 0 {
		result.AddVuln(vuln)
	}
}
