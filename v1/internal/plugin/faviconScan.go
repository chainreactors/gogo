package plugin

import (
	. "github.com/chainreactors/gogo/pkg"
	"github.com/chainreactors/gogo/pkg/dsl"
	"github.com/chainreactors/gogo/pkg/fingers"
	"github.com/chainreactors/logs"
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
	content := GetBody(resp)

	// MD5 hash匹配
	md5h := dsl.Md5Hash(content)
	if Md5Fingers[md5h] != "" {
		result.AddFramework(&fingers.Framework{Name: Md5Fingers[md5h], From: "ico"})
		return
	}

	// mmh3 hash匹配,指纹来自kscan
	mmh3h := dsl.Mmh3Hash32(content)
	if Mmh3Fingers[mmh3h] != "" {
		result.AddFramework(&fingers.Framework{Name: Mmh3Fingers[mmh3h], From: "ico"})
		return
	}
	return
}
