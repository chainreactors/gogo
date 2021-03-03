package Scan

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"getitle/src/Utils"
	"os"
)

// 信息收集插件,通过匹配http服务的favicon md5值判断CMS
func FaviconScan(result *Utils.Result) {
	var fingers map[string]interface{}

	err := json.Unmarshal([]byte(Utils.LoadFingers("md5")), &fingers)
	if err != nil {
		println("[-] md5 fingers load FAIL!")
		os.Exit(0)
	}

	conn := Utils.HttpConn(2)
	resp, err := conn.Get(Utils.GetURL(result) + "/favicon.ico")
	if err != nil {
		return
	}
	if resp.StatusCode != 200 {
		return
	}
	content := string(Utils.GetBody(resp))
	m := md5.Sum([]byte(content))
	ms := hex.EncodeToString(m[:])
	if fingers[ms] != "" {
		result.Framework = fingers[ms].(string)
	}
}
