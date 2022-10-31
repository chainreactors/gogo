package plugin

import (
	. "github.com/chainreactors/gogo/v2/pkg"
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
	if resp.StatusCode != 200 {
		return
	}
	content := parsers.ReadBody(resp)

	// MD5 hash匹配
	md5h := parsers.Md5Hash(content)
	if Md5Fingers[md5h] != "" {
		result.AddFramework(&parsers.Framework{Name: Md5Fingers[md5h], From: parsers.FrameFromICO})
		return
	}

	// mmh3 hash匹配,指纹来自kscan
	mmh3h := parsers.Mmh3Hash32(content)
	if Mmh3Fingers[mmh3h] != "" {
		result.AddFramework(&parsers.Framework{Name: Mmh3Fingers[mmh3h], From: parsers.FrameFromICO})
		return
	}
	return
}
