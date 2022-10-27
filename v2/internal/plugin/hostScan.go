package plugin

import (
	. "github.com/chainreactors/gogo/v2/pkg"
	"github.com/chainreactors/gogo/v2/pkg/fingers"
	"github.com/chainreactors/gogo/v2/pkg/utils"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/parsers"
	"net/http"
)

func hostScan(result *Result) {
	url := result.GetBaseURL()
	conn := result.GetHttpConn(RunOpt.Delay)
	if len(result.HttpHosts) > 5 {
		//经验公式: 绑定超过2个host可以认为是cdn, 5个留点冗余
		return
	}

	req, _ := http.NewRequest("GET", url, nil)
	vuln := &fingers.Vuln{Name: "host", Detail: map[string]interface{}{}, SeverityLevel: fingers.INFO}
	for _, host := range result.HttpHosts {
		req.Host = host
		resp, err := conn.Do(req)
		if err != nil {
			continue
		}
		logs.Log.Debugf("request host %s, %d for %s", url, resp.StatusCode, host)
		if resp.StatusCode != 200 {
			continue
		}
		body := parsers.ReadBody(resp)
		oldbody, _, _ := parsers.SplitHttpRaw([]byte(result.Content))

		//hash := dsl.Md5Hash(body)[:4] // 因为头中经常有随机值, 因此hash通过body判断
		if len(oldbody) != len(body) {
			if result.CurrentHost == "" {
				result.CurrentHost = host
			}
			//if result.CurrentHost == "" {
			result.Host = host
			//}
			vuln.Detail[host] = utils.AsciiEncode(parsers.MatchTitle(string(body)))
		}
	}
	if len(vuln.Detail) > 0 {
		result.AddVuln(vuln)
	}
}
