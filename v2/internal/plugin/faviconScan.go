package plugin

import (
	. "github.com/chainreactors/gogo/v2/pkg"
	"github.com/chainreactors/gogo/v2/pkg/fingers"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/parsers"
)

// -v
// 信息收集插件,通过匹配http服务的favicon md5值判断CMS
func faviconScan(result *Result) {
	var err error
	conn := result.GetHttpConn(RunOpt.Delay)
	url := result.GetURL() + "/favicon.ico"
	resp, err := conn.Get(url)
	if err != nil {
		logs.Log.Debugf("request favicon %s %s", url, err.Error())
		return
	}
	logs.Log.Debugf("request favicon %s %d", url, resp.StatusCode)
	if resp.StatusCode == 200 {
		body := parsers.ReadBody(resp)
		content := map[string]string{
			"md5":  parsers.Md5Hash(body),
			"mmh3": parsers.Mmh3Hash32(body),
		}

		frame, ok := fingers.FaviconMatch(content)
		if ok {
			result.AddFramework(frame)
			return
		}
	}

	sender := func(sendData string) ([]byte, bool) {
		conn := result.GetHttpConn(RunOpt.Delay)
		url := result.GetURL() + sendData
		logs.Log.Debugf("favicon active detect: %s", url)
		resp, err := conn.Get(url)
		if err == nil && resp.StatusCode == 200 {
			return parsers.ReadBody(resp), true
		} else {
			return nil, false
		}
	}

	if RunOpt.VersionLevel < 2 {
		return
	}

	for _, favicon := range ActiveFavicons {
		frame, ok := fingers.FaviconActiveMatch(favicon, RunOpt.VersionLevel, sender)
		if ok {
			result.AddFramework(frame)
			return
		}
	}
	return
}
