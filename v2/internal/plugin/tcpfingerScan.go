package plugin

import (
	. "github.com/chainreactors/gogo/v2/pkg"
	"github.com/chainreactors/gogo/v2/pkg/fingers"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/parsers"
)

func tcpFingerScan(result *Result) {
	// 如果是http协议,则判断cms,如果是tcp则匹配规则库.暂时不考虑udp
	if Proxy != nil {
		// 如果存在http代理，跳过tcp指纹识别
		return
	}

	sender := func(sendData []byte) ([]byte, bool) {
		target := result.GetTarget()
		logs.Log.Debugf("active detect: , data: ", target, sendData)
		conn, err := NewSocket("tcp", target, RunOpt.Delay)
		if err != nil {
			logs.Log.Debugf("active detect %s error, %s", target, err.Error())
			return nil, false
		}
		defer conn.Close()

		data, err := conn.QuickRequest(sendData, 1024)
		if err != nil {
			return nil, false
		}

		return data, true
	}

	var alreadyFrameworks = make(map[string]bool)
	for _, finger := range TcpFingers[result.Port] {
		// 通过port进行部分tcp指纹的优先探测, 节省爆破时间
		frame, vuln := tcpFingerMatch(result, finger, sender)
		alreadyFrameworks[finger.Name] = true
		if frame != nil {
			if vuln != nil {
				result.AddVuln(vuln)
			}
			result.AddFramework(frame)
			if result.Protocol == "tcp" {
				// 如果是tcp协议,并且识别到一个指纹,则退出.
				// 如果是http协议,可能存在多个指纹,则继续进行扫描
				return
			}
		}
	}

	for _, fs := range TcpFingers {
		for _, finger := range fs {
			if _, ok := alreadyFrameworks[finger.Name]; ok {
				continue
			} else {
				alreadyFrameworks[finger.Name] = true
			}

			frame, vuln := tcpFingerMatch(result, finger, sender)
			if frame != nil {
				if vuln != nil {
					result.AddVuln(vuln)
				}
				result.AddFramework(frame)
				if result.Protocol == "tcp" {
					return
				}
			}
		}
	}
	return
}

func tcpFingerMatch(result *Result, finger *fingers.Finger, sender func(sendData []byte) ([]byte, bool)) (*parsers.Framework, *parsers.Vuln) {
	frame, vuln, ok := fingers.FingerMatcher(finger, result.ContentMap(), RunOpt.VersionLevel, sender)
	if ok {
		return frame, vuln
	}
	return nil, nil
}
