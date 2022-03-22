package scan

import (
	"getitle/src/pkg"
)

// -v
// 信息收集插件,通过匹配http服务的favicon md5值判断CMS
func faviconScan(result *pkg.Result) {
	var err error
	conn := pkg.HttpConn(RunOpt.Delay)
	url := result.GetURL()
	pkg.Log.Debug("request favicon " + result.GetURL() + "/favicon.ico")
	resp, err := conn.Get(url + "/favicon.ico")
	if err != nil {
		return
	}
	if resp.StatusCode != 200 {
		return
	}
	content := pkg.GetBody(resp)

	// MD5 hash匹配
	md5h := pkg.Md5Hash(content)
	if pkg.Md5Fingers[md5h] != "" {
		result.AddFramework(&pkg.Framework{Name: pkg.Md5Fingers[md5h], Version: "ico"})
		return
	}

	// mmh3 hash匹配,指纹来自kscan
	mmh3h := pkg.Mmh3Hash32(content)
	if pkg.Mmh3Fingers[mmh3h] != "" {
		result.AddFramework(&pkg.Framework{Name: pkg.Mmh3Fingers[mmh3h], Version: "ico"})
		return
	}
	return
}
