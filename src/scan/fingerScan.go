package scan

import (
	"getitle/src/pkg"
	"net"
	"strings"
)

func fingerScan(result *pkg.Result) {
	//如果是http协议,则判断cms,如果是tcp则匹配规则库.暂时不考虑udp
	if result.IsHttp() {
		getFramework(result, pkg.HttpFingers, httpFingerMatch)
	} else {
		getFramework(result, pkg.TcpFingers, tcpFingerMatch)
	}
	return
}

func getFramework(result *pkg.Result, fingermap pkg.FingerMapper, matcher func(*pkg.Result, *pkg.Finger) (*pkg.Framework, *pkg.Vuln)) {
	// 优先匹配默认端口,第一次循环只匹配默认端口
	//var fs pkg.Frameworks
	var alreadyFrameworks pkg.Fingers
	for _, finger := range fingermap.GetFingers(result.Port) {
		framework, vuln := matcher(result, finger)
		alreadyFrameworks = append(alreadyFrameworks, finger)
		if framework != nil {
			//fs = append(fs, framework)
			result.AddFramework(framework)
			if result.Protocol == "tcp" {
				// 如果是tcp协议,并且识别到一个指纹,则退出.
				// 如果是http协议,可能存在多个指纹,则进行扫描
				return
			}
		}
		if vuln != nil {
			result.AddVuln(vuln)
		}
	}

	for port, fingers := range fingermap {
		if port == result.Port {
			// 跳过已经扫过的默认端口
			continue
		}
		for _, finger := range fingers {
			if alreadyFrameworks.Contain(finger) {
				continue
			} else {
				alreadyFrameworks = append(alreadyFrameworks, finger)
			}
			framework, vuln := matcher(result, finger)
			if framework != nil {
				//fs = append(fs, framework)
				if result.Protocol == "tcp" {
					return
				}
			}
			if vuln != nil {
				result.AddVuln(vuln)
			}
		}
	}
	return
}

func httpFingerMatch(result *pkg.Result, finger *pkg.Finger) (*pkg.Framework, *pkg.Vuln) {
	resp := result.Httpresp
	content := result.Content
	var body string
	var rerequest bool
	//var cookies map[string]string
	if RunOpt.VersionLevel >= 1 && finger.SendDataStr != "" {
		// 如果level大于1,并且存在主动发包, 则重新获取resp与content
		conn := pkg.HttpConn(RunOpt.Delay)
		tmpresp, err := conn.Get(result.GetURL() + finger.SendDataStr)
		if err == nil {
			pkg.Log.Debugf("request finger %s %d for %s", result.GetURL()+finger.SendDataStr, tmpresp.StatusCode, finger.Name)
			resp = tmpresp
			content, body = pkg.GetHttpRaw(resp)
			rerequest = true
		} else {
			pkg.Log.Debugf("request finger %s %s for %s", result.GetURL()+finger.SendDataStr, err.Error(), finger.Name)
		}
	}

	framework, vuln, ok := fingerMatcher(finger, content)
	if ok { // 如果已经匹配到一个指纹,则略过头匹配
		if rerequest {
			// 如果主动发包匹配到了指纹,则重新进行信息收集
			pkg.CollectHttpInfo(result, resp, content, body)
		}
		return framework, vuln
	}
	return nil, nil
}

func tcpFingerMatch(result *pkg.Result, finger *pkg.Finger) (*pkg.Framework, *pkg.Vuln) {
	content := result.Content
	var data []byte
	var err error

	// 某些规则需要主动发送一个数据包探测
	if finger.SendDataStr != "" && RunOpt.VersionLevel >= finger.Level {
		pkg.Log.Debugf("request finger %s for %s", result.GetTarget(), finger.Name)
		var conn net.Conn
		conn, err = pkg.TcpSocketConn(result.GetTarget(), 2)
		if err != nil {
			return nil, nil
		}
		data, err = pkg.SocketSend(conn, finger.SendData, 1024)
		// 如果报错为EOF,则需要重新建立tcp连接
		if err != nil {
			return nil, nil
		}
	}
	// 如果主动探测有回包,则正则匹配回包内容, 若主动探测没有返回内容,则直接跳过该规则
	if len(data) != 0 {
		content = string(data)
	}

	framework, vuln, ok := fingerMatcher(finger, content)
	if ok {
		return framework, vuln
	}
	return nil, nil
}

func fingerMatcher(finger *pkg.Finger, content string) (*pkg.Framework, *pkg.Vuln, bool) {
	// 漏洞匹配优先
	for _, reg := range pkg.Compiled[finger.Name+"_vuln"] {
		res, ok := pkg.CompiledMatch(reg, content)
		if ok {
			var vuln *pkg.Vuln
			if finger.Info != "" {
				vuln = &pkg.Vuln{Name: finger.Info, Severity: "info"}
			} else if finger.Vuln != "" {
				vuln = &pkg.Vuln{Name: finger.Vuln, Severity: "high"}
			}
			return &pkg.Framework{Name: finger.Name, Version: res}, vuln, true
		}
	}

	// body匹配
	for _, bodyReg := range finger.Regexps.Body {
		var body string
		if finger.Protocol == "http" {
			cs := strings.Split(content, "\r\n\r\n")
			if len(cs) > 1 {
				body = cs[1]
			}
		} else {
			body = content
		}
		if strings.Contains(body, bodyReg) {
			return &pkg.Framework{Name: finger.Name, Version: ""}, nil, true
		}
	}

	// 正则匹配
	for _, reg := range pkg.Compiled[finger.Name] {
		res, ok := pkg.CompiledMatch(reg, content)
		if ok {
			return &pkg.Framework{Name: finger.Name, Version: res}, nil, true
		}
	}

	// MD5 匹配
	for _, md5s := range finger.Regexps.MD5 {
		if md5s == pkg.Md5Hash([]byte(content)) {
			return &pkg.Framework{Name: finger.Name}, nil, true
		}
	}

	// mmh3 匹配
	for _, mmh3s := range finger.Regexps.MMH3 {
		if mmh3s == pkg.Mmh3Hash32([]byte(content)) {
			return &pkg.Framework{Name: finger.Name}, nil, true
		}
	}

	// http头匹配, http协议特有的匹配
	if finger.Protocol != "http" {
		return nil, nil, false
	}

	for _, headerReg := range finger.Regexps.Header {
		headerstr := strings.ToLower(strings.Split(content, "\r\n\r\n")[0])
		if strings.Contains(headerstr, strings.ToLower(headerReg)) {
			return &pkg.Framework{Name: finger.Name}, nil, true
		}
	}
	return nil, nil, false
}
