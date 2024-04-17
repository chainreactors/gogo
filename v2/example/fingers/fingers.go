package main

import (
	"github.com/chainreactors/fingers/fingers"
	"github.com/chainreactors/utils"
	"sigs.k8s.io/yaml"
	"strings"
)

// 调用pkg中的fingers包实现指纹识别的功能
func main() {
	// 1. 定义一个指纹规则
	// 2. 编译指纹规则
	// 3. 识别指纹

	examplefinger := `
name: kibana
focus: true
default_port:
  - '9200'
rule:
  - regexps:
      body:
      - Kibana
`
	exampleResp := "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Length: 6\r\nConnection: keep-alive\r\nDate: Thu, 08 Apr 2021 08:00:00 GMT\r\nServer: Kibana\r\n\r\nKibana"
	var f *fingers.Finger
	err := yaml.Unmarshal([]byte(strings.TrimSpace(examplefinger)), &f)
	if err != nil {
		panic(err)
	}

	// utils.ParsePorts 主要用来实现默认端口的处理提高tcp指纹识别的速度, 可传入nil
	err = f.Compile(utils.ParsePorts)
	if err != nil {
		panic(err)
	}

	// level 0 表示仅被动
	// level 1 表示打开主动指纹识别, 需配置sender
	frame, vuln, ok := f.Match(map[string]interface{}{"content": []byte(strings.ToLower(exampleResp))}, 0, nil)
	if ok {
		if frame != nil {
			println(frame.String())
		}
		if vuln != nil {
			println(vuln.String())
		}
	}
}
