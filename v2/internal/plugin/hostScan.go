package plugin

import (
	. "github.com/chainreactors/gogo/v2/pkg"
	"github.com/chainreactors/gogo/v2/pkg/utils"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/parsers"
	"net/http"
	"strconv"
	"strings"
)

func hostScan(result *Result) {
	url := result.GetBaseURL()
	conn := result.GetHttpConn(RunOpt.Delay)
	if len(result.HttpHosts) > 5 {
		//经验公式: 绑定超过2个host可以认为是cdn, 5个留点冗余
		return
	}

	req, _ := http.NewRequest("GET", url, nil)
	vuln := &parsers.Vuln{Name: "host", Detail: map[string]interface{}{}, SeverityLevel: parsers.SeverityINFO}
	for _, host := range result.HttpHosts {
		req.Host = host
		resp, err := conn.Do(req)
		if err != nil {
			continue
		}
		logs.Log.Debugf("request host %s, %d for %s", url, resp.StatusCode, host)
		if strings.HasPrefix(strconv.Itoa(resp.StatusCode), "40") {
			continue
		}
		body := parsers.ReadBody(resp)
		title := parsers.MatchTitle(string(body))

		if result.Title != title {
			if result.CurrentHost == "" {
				result.CurrentHost = host
			}
			result.Host = host
			vuln.Detail[host] = utils.AsciiEncode(title)
		}
	}
	if len(vuln.Detail) > 0 {
		result.AddVuln(vuln)
	}
}
