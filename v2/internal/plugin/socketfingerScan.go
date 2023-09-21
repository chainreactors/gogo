package plugin

import (
	. "github.com/chainreactors/gogo/v2/pkg"
	"github.com/chainreactors/gogo/v2/pkg/fingers"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/parsers"
)

var (
	TCP = "tcp"
	UDP = "udp"
)

func tcpFingerScan(result *Result) {
	// 如果是http协议,则判断cms,如果是tcp则匹配规则库.暂时不考虑udp
	if Proxy != nil {
		// 如果存在http代理，跳过tcp指纹识别
		return
	}

	tcpsender := func(sendData []byte) ([]byte, bool) {
		target := result.GetTarget()
		logs.Log.Debugf("active detect: , data: ", target, sendData)
		conn, err := NewSocket(TCP, target, RunOpt.Delay)
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

	udpsender := func(sendData []byte) ([]byte, bool) {
		target := result.GetTarget()
		logs.Log.Debugf("active detect: , data: ", target, sendData)
		conn, err := NewSocket(UDP, target, RunOpt.Delay)
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
	for _, finger := range SocketFingers[result.Port] {
		// 通过port进行部分tcp指纹的优先探测, 节省爆破时间
		frame, vuln := socketFingerMatch(result, finger, tcpsender, udpsender)
		alreadyFrameworks[finger.Name] = true
		if frame != nil {
			if vuln != nil {
				result.AddVuln(vuln)
			}
			result.AddFramework(frame)
			return
		}
	}

	for _, fs := range SocketFingers {
		for _, finger := range fs {
			if _, ok := alreadyFrameworks[finger.Name]; ok {
				continue
			} else {
				alreadyFrameworks[finger.Name] = true
			}

			frame, vuln := socketFingerMatch(result, finger, tcpsender, udpsender)
			if frame != nil {
				if vuln != nil {
					result.AddVuln(vuln)
				}
				result.AddFramework(frame)
				// tcp/udp仅支持识别一个指纹
				return
			}
		}
	}
	return
}

func socketFingerMatch(result *Result, finger *fingers.Finger, tcpsender, udpsender func(sendData []byte) ([]byte, bool)) (*parsers.Framework, *parsers.Vuln) {
	var frame *parsers.Framework
	var vuln *parsers.Vuln
	var ok bool
	if finger.Protocol == TCP {
		frame, vuln, ok = fingers.FingerMatcher(finger, result.ContentMap(), RunOpt.VersionLevel, tcpsender)
	} else if finger.Protocol == UDP {
		frame, vuln, ok = fingers.FingerMatcher(finger, result.ContentMap(), RunOpt.VersionLevel, udpsender)
	}

	if ok {
		return frame, vuln
	}
	return nil, nil
}
