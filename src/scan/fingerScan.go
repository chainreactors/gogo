package scan

import (
	"getitle/src/utils"
	"net"
	"strings"
)

func fingerScan(result *utils.Result) {
	//如果是http协议,则判断cms,如果是tcp则匹配规则库.暂时不考虑udp
	if result.IsHttp() {
		getFramework(result, utils.HttpFingers, httpFingerMatch)
	} else {
		getFramework(result, utils.TcpFingers, tcpFingerMatch)
	}
	return
}

func httpFingerMatch(result *utils.Result, finger *utils.Finger) *utils.Framework {
	resp := result.Httpresp
	content := result.Content
	//var cookies map[string]string
	if finger.SendDataStr != "" && RunOpt.VersionLevel >= 1 {
		conn := utils.HttpConn(2)
		resp, err := conn.Get(result.GetURL() + finger.SendDataStr)
		if err != nil {
			return nil
		}
		if err == nil {
			content = string(utils.GetBody(resp))
		}

	}

	framework, ok := fingerMatcher(result, finger, content)
	if ok {
		return framework
	}
	// http头匹配
	for _, header := range finger.Regexps.Header {
		var headerstr string
		if resp == nil {
			headerstr = strings.ToLower(strings.Split(content, "\r\n\r\n")[0])
		} else {
			headerstr = strings.ToLower(utils.GetHeaderstr(resp))
		}

		if strings.Contains(headerstr, strings.ToLower(header)) {
			return handlerMatchedResult(result, finger, "", content)
		}
	}
	return nil
}

func getFramework(result *utils.Result, fingermap *utils.FingerMapper, matcher func(*utils.Result, *utils.Finger) *utils.Framework) {
	// 优先匹配默认端口,第一次循环只匹配默认端口
	var fs utils.Frameworks
	for _, finger := range fingermap.GetFingers(result.Port) {
		framework := matcher(result, finger)
		if framework != nil {
			fs = append(fs, framework)
		}
	}

	if result.Protocol == "tcp" && !result.NoFramework() {
		// 如果是tcp协议,并且识别到一个指纹,则退出.
		// 如果是http协议,可能存在多个指纹,则进行扫描
		return
	}

	for port, fingers := range *fingermap {
		if port == result.Port {
			// 跳过已经扫过的默认端口
			continue
		}
		for _, finger := range fingers {
			framework := matcher(result, finger)
			if framework != nil {
				fs = append(fs, framework)
			}
		}
	}
	result.AddFrameworks(fs)
	return
}

func tcpFingerMatch(result *utils.Result, finger *utils.Finger) *utils.Framework {
	content := result.Content
	var data []byte
	var err error

	// 某些规则需要主动发送一个数据包探测
	if finger.SendDataStr != "" && RunOpt.VersionLevel >= finger.Level {
		var conn net.Conn
		conn, err = utils.TcpSocketConn(result.GetTarget(), 2)
		if err != nil {
			return nil
		}
		data, err = utils.SocketSend(conn, finger.SendData, 1024)
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

func handlerMatchedResult(result *utils.Result, finger *utils.Finger, res, content string) *utils.Framework {
	if RunOpt.VersionLevel >= 1 && finger.SendDataStr != "" && content != "" { // 需要主动发包的指纹重新收集信息
		result.Content = content
		result.InfoFilter()
	}
	return &utils.Framework{Name: finger.Name, Version: res}
}

func fingerMatcher(result *utils.Result, finger *utils.Finger, content string) (*utils.Framework, bool) {
	// 漏洞匹配优先
	for _, reg := range utils.Compiled[finger.Name+"_vuln"] {
		res, ok := utils.CompiledMatch(reg, content)
		if ok {
			if finger.Info != "" {
				result.AddVuln(&utils.Vuln{Name: finger.Info, Severity: "info"})
			} else if finger.Vuln != "" {
				result.AddVuln(&utils.Vuln{Name: finger.Vuln, Severity: "high"})
			}
			return handlerMatchedResult(result, finger, res, content), true
		}
	}

	// body匹配
	for _, body := range finger.Regexps.Body {
		if strings.Contains(content, body) {

			return handlerMatchedResult(result, finger, "", content), true
		}
	}

	// 正则匹配
	for _, reg := range utils.Compiled[finger.Name] {
		res, ok := utils.CompiledMatch(reg, content)
		if ok {

			return handlerMatchedResult(result, finger, res, content), true
		}
	}

	// MD5 匹配
	for _, md5s := range finger.Regexps.MD5 {
		if md5s == utils.Md5Hash([]byte(content)) {
			return &utils.Framework{Name: finger.Name}, true
		}
	}

	// mmh3 匹配
	for _, mmh3s := range finger.Regexps.MMH3 {
		if mmh3s == utils.Mmh3Hash32([]byte(content)) {
			return &utils.Framework{Name: finger.Name}, true
		}
	}
	return nil, false
}
