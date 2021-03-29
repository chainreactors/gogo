package Scan

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"getitle/src/Utils"
	"github.com/twmb/murmur3"
	"os"
)

// -v
// 信息收集插件,通过匹配http服务的favicon md5值判断CMS
func FaviconScan(result *Utils.Result) {
	var err error
	conn := Utils.HttpConn(2)
	url := Utils.GetURL(result)
	resp, err := conn.Get(url + "/favicon.ico")
	if err != nil {
		return
	}
	if resp.StatusCode != 200 {
		return
	}
	content := Utils.GetBody(resp)

	// MD5 hash匹配
	var md5fingers map[string]string
	err = json.Unmarshal([]byte(Utils.LoadFingers("md5")), &md5fingers)
	if err != nil {
		println("[-] md5 fingers load FAIL!")
		os.Exit(0)
	}
	md5h := md5Hash(content)
	if md5fingers[md5h] != "" {
		result.Framework = md5fingers[md5h]
		return
	}

	// mmh3 hash匹配,指纹来自kscan
	var mmh3fingers map[string]string
	err = json.Unmarshal([]byte(Utils.LoadFingers("mmh3")), &mmh3fingers)
	if err != nil {
		println("[-] mmh3 fingers load FAIL!")
		os.Exit(0)
	}
	mmh3h := mmh3Hash32(content)
	if mmh3fingers[mmh3h] != "" {
		result.Framework = mmh3fingers[mmh3h]
		return
	}
	return
}

func md5Hash(raw []byte) string {
	m := md5.Sum(raw)
	return hex.EncodeToString(m[:])
}

func mmh3Hash32(raw []byte) string {
	var h32 = murmur3.New32()
	_, _ = h32.Write(standBase64(raw))
	return fmt.Sprintf("%d", h32.Sum32())
}

func standBase64(braw []byte) []byte {
	bckd := base64.StdEncoding.EncodeToString(braw)
	var buffer bytes.Buffer
	for i := 0; i < len(bckd); i++ {
		ch := bckd[i]
		buffer.WriteByte(ch)
		if (i+1)%76 == 0 {
			buffer.WriteByte('\n')
		}
	}
	buffer.WriteByte('\n')
	return buffer.Bytes()
}
