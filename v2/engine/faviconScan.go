package engine

import (
	. "github.com/chainreactors/gogo/v2/pkg"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/utils/encode"
	"github.com/chainreactors/utils/httputils"
)

// -v
// 信息收集插件,通过匹配http服务的favicon md5值判断CMS
func FaviconScan(opt *RunnerOption, result *Result) {
	var err error
	conn := result.GetHttpConn(opt.Delay)
	url := result.GetURL() + "/favicon.ico"
	resp, err := conn.Get(url)
	if err != nil {
		logs.Log.Debugf("request favicon %s %s", url, err.Error())
		return
	}
	logs.Log.Debugf("request favicon %s %d", url, resp.StatusCode)
	if resp.StatusCode == 200 {
		body := httputils.ReadBody(resp)
		md5h := encode.Md5Hash(body)
		mmh3h := encode.Mmh3Hash32(body)
		logs.Log.Debugf("%s favicon %s %s", url, md5h, mmh3h)
		frame := FingerEngine.Favicons.HashMatch(md5h, mmh3h)
		if frame != nil {
			result.AddFramework(frame)
			return
		}
	}

	if opt.VersionLevel < 2 {
		return
	}
	//sender := func(sendData string) ([]byte, bool) {
	//	conn := result.GetHttpConn(RunOpt.Delay)
	//	url := result.GetURL() + sendData
	//	logs.Log.Debugf("favicon active detect: %s", url)
	//	resp, err := conn.Get(url)
	//	if err == nil && resp.StatusCode == 200 {
	//		return parsers.ReadBody(resp), true
	//	} else {
	//		return nil, false
	//	}
	//}
	//for _, favicon := range ActiveFavicons {
	//	frame, ok := fingers.FaviconActiveMatch(favicon, RunOpt.VersionLevel, sender)
	//	if ok {
	//		result.AddFramework(frame)
	//		return
	//	}
	//}
	return
}
