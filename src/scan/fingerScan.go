package scan

import (
	"getitle/src/pkg"
	"net"
	"strings"
)

func fingerScan(result *pkg.Result) {
	//如果是http协议,则判断cms,如果是tcp则匹配规则库.暂时不考虑udp
	var fs pkg.Frameworks
	if result.IsHttp() {
		fs = getFramework(result, pkg.HttpFingers, httpFingerMatch)
	} else {
		fs = getFramework(result, pkg.TcpFingers, tcpFingerMatch)
	}
	result.AddFrameworks(fs)
	return
}

func httpFingerMatch(result *pkg.Result, finger *pkg.Finger) *pkg.Framework {
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
			resp = tmpresp
			content, body = pkg.GetHttpRaw(resp)
			rerequest = true
		}
	}

	framework, ok := fingerMatcher(result, finger, content)
	if ok { // 如果已经匹配到一个指纹,则略过头匹配
		if rerequest {
			// 如果主动发包匹配到了指纹,则重新进行信息收集
			pkg.CollectHttpInfo(result, resp, content, body)
		}
		return framework
	}

	// http头匹配, http协议特有的匹配
	for _, header := range finger.Regexps.Header {
		var headerstr string
		if resp == nil {
			headerstr = strings.ToLower(strings.Split(content, "\r\n\r\n")[0])
		} else {
			headerstr = strings.ToLower(pkg.GetHeaderstr(resp))
		}

		if strings.Contains(headerstr, strings.ToLower(header)) {
			if rerequest {
				// 如果主动发包匹配到了指纹,则重新进行信息收集
				pkg.CollectHttpInfo(result, resp, content, body)
			}
			return &pkg.Framework{Name: finger.Name}
		}
	}
	return nil
}

func getFramework(result *pkg.Result, fingermap pkg.FingerMapper, matcher func(*pkg.Result, *pkg.Finger) *pkg.Framework) pkg.Frameworks {
	// 优先匹配默认端口,第一次循环只匹配默认端口
	var fs pkg.Frameworks
	for _, finger := range fingermap.GetFingers(result.Port) {
		framework := matcher(result, finger)
		if framework != nil {
			fs = append(fs, framework)
			if result.Protocol == "tcp" {
				// 如果是tcp协议,并且识别到一个指纹,则退出.
				// 如果是http协议,可能存在多个指纹,则进行扫描
				return fs
			}
		}
	}

	for port, fingers := range fingermap {
		if port == result.Port {
			// 跳过已经扫过的默认端口
			continue
		}
		for _, finger := range fingers {
			framework := matcher(result, finger)
			if framework != nil {
				fs = append(fs, framework)
				if result.Protocol == "tcp" {
					return fs
				}
			}
		}
	}
	return fs
}

func tcpFingerMatch(result *pkg.Result, finger *pkg.Finger) *pkg.Framework {
	content := result.Content
	var data []byte
	var err error

	// 某些规则需要主动发送一个数据包探测
	if finger.SendDataStr != "" && RunOpt.VersionLevel >= finger.Level {
		var conn net.Conn
		conn, err = pkg.TcpSocketConn(result.GetTarget(), 2)
		if err != nil {
			return nil
		}
		data, err = pkg.SocketSend(conn, finger.SendData, 1024)
		// 如果报错为EOF,则需要重新建立tcp连接
		if err != nil {
			return nil
		}
	}
	// 如果主动探测有回包,则正则匹配回包内容, 若主动探测没有返回内容,则直接跳过该规则
	if len(data) != 0 {
		content = string(data)
	}

	framework, ok := fingerMatcher(result, finger, content)
	if ok {
		return framework
	}
	return nil
}

func fingerMatcher(result *pkg.Result, finger *pkg.Finger, content string) (*pkg.Framework, bool) {
	// 漏洞匹配优先
	for _, reg := range pkg.Compiled[finger.Name+"_vuln"] {
		res, ok := pkg.CompiledMatch(reg, content)
		if ok {
			if finger.Info != "" {
				result.AddVuln(&pkg.Vuln{Name: finger.Info, Severity: "info"})
			} else if finger.Vuln != "" {
				result.AddVuln(&pkg.Vuln{Name: finger.Vuln, Severity: "high"})
			}
			return &pkg.Framework{Name: finger.Name, Version: res}, true
		}
	}

	// body匹配
	for _, body := range finger.Regexps.Body {
		if strings.Contains(content, body) {

			return &pkg.Framework{Name: finger.Name, Version: ""}, true
		}
	}

	// 正则匹配
	for _, reg := range pkg.Compiled[finger.Name] {
		res, ok := pkg.CompiledMatch(reg, content)
		if ok {

			return &pkg.Framework{Name: finger.Name, Version: res}, true
		}
	}

	// MD5 匹配
	for _, md5s := range finger.Regexps.MD5 {
		if md5s == pkg.Md5Hash([]byte(content)) {
			return &pkg.Framework{Name: finger.Name}, true
		}
	}

	// mmh3 匹配
	for _, mmh3s := range finger.Regexps.MMH3 {
		if mmh3s == pkg.Mmh3Hash32([]byte(content)) {
			return &pkg.Framework{Name: finger.Name}, true
		}
	}
	return nil, false
}
