package fingers

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/twmb/murmur3"
	"regexp"
	"strings"
)

func Md5Hash(raw []byte) string {
	m := md5.Sum(raw)
	return hex.EncodeToString(m[:])
}

func Mmh3Hash32(raw []byte) string {
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

func compiledMatch(reg *regexp.Regexp, s string) (string, bool) {
	matched := reg.FindStringSubmatch(s)
	if matched == nil {
		return "", false
	}
	if len(matched) == 1 {
		return "", true
	} else {
		return strings.TrimSpace(matched[1]), true
	}
}

func FingerMatcher(finger *Finger, content string) (*Framework, *Vuln, bool) {
	// 漏洞匹配优先
	for _, reg := range finger.Regexps.CompiledVulnRegexp {
		res, ok := compiledMatch(reg, content)
		if ok {
			var vuln *Vuln
			if finger.Info != "" {
				vuln = &Vuln{Name: finger.Info, Severity: "info"}
			} else if finger.Vuln != "" {
				vuln = &Vuln{Name: finger.Vuln, Severity: "high"}
			}
			return &Framework{Name: finger.Name, Version: res}, vuln, true
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
			return &Framework{Name: finger.Name, Version: ""}, nil, true
		}
	}

	// 正则匹配
	for _, reg := range finger.Regexps.CompliedRegexp {
		res, ok := compiledMatch(reg, content)
		if ok {
			return &Framework{Name: finger.Name, Version: res}, nil, true
		}
	}

	// MD5 匹配
	for _, md5s := range finger.Regexps.MD5 {
		if md5s == Md5Hash([]byte(content)) {
			return &Framework{Name: finger.Name}, nil, true
		}
	}

	// mmh3 匹配
	for _, mmh3s := range finger.Regexps.MMH3 {
		if mmh3s == Mmh3Hash32([]byte(content)) {
			return &Framework{Name: finger.Name}, nil, true
		}
	}

	// http头匹配, http协议特有的匹配
	if finger.Protocol != "http" {
		return nil, nil, false
	}

	for _, headerReg := range finger.Regexps.Header {
		headerstr := strings.ToLower(strings.Split(content, "\r\n\r\n")[0])
		if strings.Contains(headerstr, strings.ToLower(headerReg)) {
			return &Framework{Name: finger.Name}, nil, true
		}
	}
	return nil, nil, false
}
