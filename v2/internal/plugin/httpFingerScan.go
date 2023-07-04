package plugin

import (
	. "github.com/chainreactors/gogo/v2/pkg"
	"github.com/chainreactors/parsers"
)

func httpFingerScan(result *Result) {
	passiveHttpMatch(result)
	if RunOpt.VersionLevel > 0 {
		activeHttpMatch(result)
	}
	return
}

func passiveHttpMatch(result *Result) {
	for _, f := range PassiveHttpFingers {
		frame, vuln, ok := f.Match(result.ContentMap(), 0, nil)
		if ok {
			if vuln != nil {
				result.AddVuln(vuln)
			}
			result.AddFramework(frame)
		} else {
			// 如果没有匹配到,则尝试使用history匹配
			historyMatch(result)
		}
	}
}

func activeHttpMatch(result *Result) {
	sender := func(sendData []byte) ([]byte, bool) {
		conn := result.GetHttpConn(RunOpt.Delay)
		url := result.GetURL() + string(sendData)
		resp, err := conn.Get(url)
		if err == nil {
			return parsers.ReadRaw(resp), true
		} else {
			return nil, false
		}
	}

	for _, f := range ActiveHttpFingers {
		// 当前gogo中最大指纹level为1, 因此如果调用了这个函数, 则认定为level1
		frame, vuln, ok := f.Match(result.ContentMap(), 1, sender)
		if ok {
			if vuln != nil {
				result.AddVuln(vuln)
			}
			result.AddFramework(frame)
		} else {
			// 如果没有匹配到,则尝试使用history匹配
			historyMatch(result)
		}
	}
}

func historyMatch(result *Result) {
	for _, content := range result.Httpresp.History {
		for _, f := range PassiveHttpFingers {
			frame, vuln, ok := f.Match(content.ContentMap(), 0, nil)
			if ok {
				if vuln != nil {
					result.AddVuln(vuln)
				}
				frame.From = 5
				result.AddFramework(frame)
			}
		}
	}
}
