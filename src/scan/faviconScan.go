package scan

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"getitle/src/utils"
	"github.com/twmb/murmur3"
)

// -v
// 信息收集插件,通过匹配http服务的favicon md5值判断CMS
func faviconScan(result *utils.Result) {
	var err error
	conn := utils.HttpConn(2)
	url := result.GetURL()
	resp, err := conn.Get(url + "/favicon.ico")
	if err != nil {
		return
	}
	if resp.StatusCode != 200 {
		return
	}
	content := utils.GetBody(resp)

	// MD5 hash匹配
	md5h := md5Hash(content)
	if utils.Md5fingers[md5h] != "" {
		result.Framework = utils.Md5fingers[md5h]
		return
	}

	// mmh3 hash匹配,指纹来自kscan
	mmh3h := mmh3Hash32(content)
	if utils.Mmh3fingers[mmh3h] != "" {
		result.Framework = utils.Mmh3fingers[mmh3h]
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
