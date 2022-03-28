package scan

import (
	. "getitle/src/fingers"
	. "getitle/src/pkg"
	"net/http"
	"strings"
)

func hostScan(result *Result) {
	url := result.GetBaseURL()
	conn := HttpConn(RunOpt.Delay)
	req, _ := http.NewRequest("GET", url, nil)
	vuln := &Vuln{Name: "host", Detail: map[string]interface{}{}, Severity: "info"}
	for _, host := range result.HttpHost {

		req.Host = host
		resp, err := conn.Do(req)
		if err != nil {
			return
		}

		if resp.StatusCode != 200 {
			continue
		}
		content, body := GetHttpRaw(resp)
		hash := Md5Hash([]byte(strings.TrimSpace(body)))[:4] // 因为头中经常有随机值, 因此hash通过body判断
		if result.Hash != hash {
			vuln.Detail[host] = AsciiEncode(GetTitle(content))
		}
	}
	if len(vuln.Detail) > 0 {
		result.AddVuln(vuln)
	}
}
