package scan

import (
	. "getitle/v1/pkg"
	. "getitle/v1/pkg/fingers"
	"net/http"
	"strings"
)

func hostScan(result *Result) {
	url := result.GetBaseURL()
	conn := result.GetHttpConn(RunOpt.Delay)
	if len(result.HttpHost) > 5 {
		//经验公式: 绑定超过2个host可以认为是cdn, 5个留点冗余
		return
	}

	req, _ := http.NewRequest("GET", url, nil)
	vuln := &Vuln{Name: "host", Detail: map[string]interface{}{}, Severity: "info"}
	for _, host := range result.HttpHost {
		req.Host = host
		resp, err := conn.Do(req)
		if err != nil {
			continue
		}
		Log.Debugf("request host %s, %d for %s", url, resp.StatusCode, host)
		if resp.StatusCode != 200 {
			continue
		}
		content, body := GetHttpRaw(resp)
		hash := Md5Hash([]byte(strings.TrimSpace(body)))[:4] // 因为头中经常有随机值, 因此hash通过body判断
		if result.Hash != hash {
			//if result.CurrentHost == "" {
			result.Host = host
			//}
			vuln.Detail[host] = AsciiEncode(GetTitle(content))
		}
	}
	if len(vuln.Detail) > 0 {
		result.AddVuln(vuln)
	}
}
