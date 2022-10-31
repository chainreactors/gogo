package plugin

import (
	. "github.com/chainreactors/gogo/v2/pkg"
	"github.com/chainreactors/gogo/v2/pkg/fingers"
	"github.com/chainreactors/parsers"
)

func fingerScan(result *Result) {
	//如果是http协议,则判断cms,如果是tcp则匹配规则库.暂时不考虑udp
	if result.IsHttp() {
		sender := func(sendData []byte) (string, bool) {
			conn := result.GetHttpConn(RunOpt.Delay)
			url := result.GetURL() + string(sendData)
			resp, err := conn.Get(url)
			if err == nil {
				return string(parsers.ReadRaw(resp)), true
			} else {
				return "", false
			}
		}

		matcher := func(result *Result, finger *fingers.Finger) (*parsers.Framework, *parsers.Vuln) {
			return httpFingerMatch(result, finger, sender)
		}
		getFramework(result, HttpFingers, matcher)
	} else {
		if Proxy != nil {
			// 如果存在http代理，跳过tcp指纹识别
			return
		}
		sender := func(sendData []byte) (string, bool) {
			conn, err := NewSocket("tcp", result.GetTarget(), RunOpt.Delay)
			if err != nil {
				return "", false
			}
			data, err := conn.Request(sendData, 1024)
			//data, err := SocketSend(conn, sendData, 1024)
			if err != nil {
				return "", false
			}
			return string(data), true
		}

		matcher := func(result *Result, finger *fingers.Finger) (*parsers.Framework, *parsers.Vuln) {
			return tcpFingerMatch(result, finger, sender)
		}
		getFramework(result, TcpFingers, matcher)
	}
	return
}

func getFramework(result *Result, fingermap fingers.FingerMapper, matcher func(*Result, *fingers.Finger) (*parsers.Framework, *parsers.Vuln)) {
	// 优先匹配默认端口,第一次循环只匹配默认端口
	var alreadyFrameworks fingers.Fingers
	for _, finger := range fingermap.GetFingers(result.Port) {
		framework, vuln := matcher(result, finger)
		alreadyFrameworks = append(alreadyFrameworks, finger)
		if framework != nil {
			if vuln != nil {
				result.AddVuln(vuln)
			}
			result.AddFramework(framework)
			if result.Protocol == "tcp" {
				// 如果是tcp协议,并且识别到一个指纹,则退出.
				// 如果是http协议,可能存在多个指纹,则进行扫描
				return
			}
		}
	}

	for port, fs := range fingermap {
		if port == result.Port {
			// 跳过已经扫过的默认端口
			continue
		}
		for _, finger := range fs {
			if alreadyFrameworks.Contain(finger) {
				continue
			} else {
				alreadyFrameworks = append(alreadyFrameworks, finger)
			}
			framework, vuln := matcher(result, finger)
			if framework != nil {
				result.AddFramework(framework)
				if vuln != nil {
					result.AddVuln(vuln)
				}
				if result.Protocol == "tcp" {
					return
				}
			}
		}
	}
	return
}

func httpFingerMatch(result *Result, finger *fingers.Finger, sender func(sendData []byte) (string, bool)) (*parsers.Framework, *parsers.Vuln) {
	frame, vuln, ok := fingers.FingerMatcher(finger, result.Content, RunOpt.VersionLevel, sender)
	if ok {
		if frame.Data != "" {
			result.Title = parsers.MatchTitle(frame.Data)
		}
		return frame, vuln
	}
	return nil, nil
}

func tcpFingerMatch(result *Result, finger *fingers.Finger, sender func(sendData []byte) (string, bool)) (*parsers.Framework, *parsers.Vuln) {
	frame, vuln, ok := fingers.FingerMatcher(finger, result.Content, RunOpt.VersionLevel, sender)
	if ok {
		return frame, vuln
	}
	return nil, nil
}
