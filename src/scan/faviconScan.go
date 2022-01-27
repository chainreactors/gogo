package scan

import (
	"getitle/src/utils"
)

// -v
// 信息收集插件,通过匹配http服务的favicon md5值判断CMS
func faviconScan(result *utils.Result) {
	var err error
	conn := utils.HttpConn(2)
	url := result.GetURL()
	resp, err := conn.Get(url + "/favicon.ico")
	if err != nil {
		return
	}
	if resp.StatusCode != 200 {
		return
	}
	content := utils.GetBody(resp)

	// MD5 hash匹配
	md5h := utils.Md5Hash(content)
	if utils.Md5Fingers[md5h] != "" {
		result.AddFramework(&utils.Framework{Name: utils.Md5Fingers[md5h], Version: "ico"})
		return
	}

	// mmh3 hash匹配,指纹来自kscan
	mmh3h := utils.Mmh3Hash32(content)
	if utils.Mmh3Fingers[mmh3h] != "" {
		result.AddFramework(&utils.Framework{Name: utils.Mmh3Fingers[mmh3h], Version: "ico"})
		return
	}
	return
}
