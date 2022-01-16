package scan

import (
	"crypto/md5"
	"encoding/hex"
	"getitle/src/utils"
	"net"
	"strings"
)

func fingerScan(result *utils.Result) {
	//如果是http协议,则判断cms,如果是tcp则匹配规则库.暂时不考虑udp
	if strings.HasPrefix(result.Protocol, "http") {
		getFramework(result, utils.Httpfingers, httpFingerMatch)
	} else {
		getFramework(result, utils.Tcpfingers, tcpFingerMatch)
	}
	return
}

func httpFingerMatch(result *utils.Result, finger *utils.Finger) {
	resp := result.Httpresp
	content := result.Content
	//var cookies map[string]string
	if finger.SendData_str != "" && RunOpt.VersionLevel >= 1 {
		conn := utils.HttpConn(2)
		resp, err := conn.Get(result.GetURL() + finger.SendData_str)
		if err == nil {
			content = string(utils.GetBody(resp))
		}
	}

	// 漏洞匹配优先
	for _, reg := range utils.Compiled[finger.Name+"_vuln"] {
		res, ok := utils.CompileMatch(reg, content)
		if ok {
			handlerMatchedResult(result, finger, res, content)
			result.AddVuln(utils.Vuln{Name: finger.Vuln})
			return
		}
	}
	// html匹配
	for _, body := range finger.Regexps.Body {
		if strings.Contains(content, body) {
			result.AddFramework(utils.Framework{Name: finger.Name})
			return
		}
	}

	// 正则匹配
	for _, reg := range utils.Compiled[finger.Name] {
		res, ok := utils.CompileMatch(reg, content)
		if ok {
			handlerMatchedResult(result, finger, res, content)
			return
		}
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
			result.AddFramework(utils.Framework{Name: finger.Name})
			return
		}
	}

	//} else if finger.Regexps.Cookie != nil {
	//	for _, cookie := range finger.Regexps.Cookie {
	//		if resp == nil {
	//			if strings.Contains(content, cookie) {
	//				result.Frameworks = finger.Name
	//				return
	//			}
	//		} else if cookies[cookie] != "" {
	//			result.Frameworks = finger.Name
	//			return
	//		}
	//	}/
	// MD5 匹配
	for _, md5s := range finger.Regexps.MD5 {
		m := md5.Sum([]byte(content))
		if md5s == hex.EncodeToString(m[:]) {
			result.AddFramework(utils.Framework{Name: finger.Name})
			return
		}
	}
}

func getFramework(result *utils.Result, fingermap *utils.FingerMapper, matcher func(*utils.Result, *utils.Finger)) {
	// 优先匹配默认端口,第一遍循环只匹配默认端口
	for _, finger := range fingermap.GetFingers(result.Port) {
		matcher(result, finger)
	}

	if result.Protocol == "tcp" && !result.NoFramework() {
		// 如果是tcp协议,并且识别到一个指纹,则退出.
		// 如果是http协议,可能存在多个指纹,则进行扫描
		return
	}

	for port, fingers := range *fingermap {
		if port == result.Port {
			continue
		}
		for _, finger := range fingers {
			matcher(result, finger)
		}
	}
	return
}

func tcpFingerMatch(result *utils.Result, finger *utils.Finger) {
	content := result.Content
	var data []byte
	var err error

	// 某些规则需要主动发送一个数据包探测
	if finger.SendData_str != "" && RunOpt.VersionLevel >= finger.Level {
		var conn net.Conn
		conn, err = utils.TcpSocketConn(result.GetTarget(), 2)
		if err != nil {
			return
		}
		data, err = utils.SocketSend(conn, finger.SendData, 1024)
		// 如果报错为EOF,则需要重新建立tcp连接
		if err != nil {
			return
			//target := GetTarget(result)
			//// 如果对端已经关闭,则本地socket也关闭,并重新建立连接
			//(*result.TcpCon).Close()
			//*result.TcpCon, err = TcpSocketConn(target, time.Duration(2))
			//if err != nil {
			//	return
			//}
			//data, err = SocketSend(*result.TcpCon, []byte(finger.SendData_str), 1024)
			//
			//// 重新建立链接后再次报错,则跳过该规则匹配
			//if err != nil {
			//	result.Error = err.Error()
			//	return
			//}
		}
	}
	// 如果主动探测有回包,则正则匹配回包内容, 若主动探测没有返回内容,则直接跳过该规则
	if len(data) != 0 {
		content = string(data)
	}

	// 遍历漏洞正则
	for _, reg := range utils.Compiled[finger.Name+"_vuln"] {
		res, ok := utils.CompileMatch(reg, content)
		if ok {
			handlerMatchedResult(result, finger, res, content)
			if finger.Vuln != "" {
				result.AddVuln(utils.Vuln{Name: finger.Vuln})
			}
			return
		}
	}

	//遍历指纹正则
	for _, reg := range utils.Compiled[finger.Name] {
		res, ok := utils.CompileMatch(reg, content)
		if ok {
			handlerMatchedResult(result, finger, res, content)
			return
		}
	}
	return
}

func handlerMatchedResult(result *utils.Result, finger *utils.Finger, res, content string) {
	if result.Protocol == "tcp" {
		result.HttpStat = finger.Protocol
	}

	result.AddFramework(utils.Framework{Name: finger.Name, Version: res})

	if RunOpt.VersionLevel >= 1 && finger.SendData_str != "" && content != "" { // 需要主动发包的指纹重新收集信息
		result.InfoFilter()
	}
}
