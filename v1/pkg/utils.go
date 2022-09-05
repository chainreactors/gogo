package pkg

import (
	"fmt"
	. "github.com/chainreactors/files"
	"github.com/chainreactors/gogo/pkg/dsl"
	"github.com/chainreactors/gogo/pkg/utils"
	"github.com/chainreactors/ipcs"
	"io/ioutil"
	"net/http"
	"regexp"
	"sort"
	"strings"
)

var (
	Win  = utils.IsWin()
	Root = utils.IsRoot()
	Key  = []byte{}
)

func GetHttpRaw(resp *http.Response) string {
	var raw string

	raw += fmt.Sprintf("%s %s\r\n", resp.Proto, resp.Status)
	for k, v := range resp.Header {
		for _, i := range v {
			raw += fmt.Sprintf("%s: %s\r\n", k, i)
		}
	}
	raw += "\r\n"
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return raw
	}
	raw += string(body)
	_ = resp.Body.Close()
	return raw
}

func GetBody(resp *http.Response) []byte {
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return []byte{}
	}
	_ = resp.Body.Close()
	return body
}

func SplitHttpRaw(content string) (body, header string, ok bool) {
	cs := strings.Index(content, "\r\n\r\n")
	if cs != -1 && len(content) >= cs+4 {
		body = content[cs+4:]
		header = content[:cs]
		return body, header, true
	}
	return "", "", false
}

func AsciiEncode(s string) string {
	s = strings.TrimSpace(s)
	s = fmt.Sprintf("%q", s)
	s = strings.Trim(s, "\"")
	return s
}

func Match(regexpstr string, s string) (string, bool) {
	reg, err := regexp.Compile(regexpstr)
	if err != nil {
		return "", false
	}
	res := reg.FindStringSubmatch(s)
	if len(res) == 1 {
		return "", true
	} else if len(res) == 2 {
		return res[1], true
	}
	return "", false
}

func CompiledMatch(reg *regexp.Regexp, s string) (string, bool) {
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

func CompiledAllMatch(reg *regexp.Regexp, s string) ([]string, bool) {
	matchedes := reg.FindAllString(s, -1)
	if matchedes == nil {
		return nil, false
	}
	return matchedes, true
}

func GetHeaderstr(resp *http.Response) string {
	var headerstr = ""
	for k, v := range resp.Header {
		for _, i := range v {
			headerstr += fmt.Sprintf("%s: %s\r\n", k, i)
		}
	}
	return headerstr
}

func CompileRegexp(s string) *regexp.Regexp {
	reg, err := regexp.Compile(s)
	if err != nil {
		utils.Fatal(fmt.Sprintf("regexp string error: %s, %s", s, err.Error()))
	}
	return reg
}

func Decode(input string) []byte {
	b := dsl.Base64Decode(input)
	return UnFlate(b)
}

func FileDecode(input string) []byte {
	b := dsl.Base64Decode(input)
	b = dsl.XorEncode(b, Key, 0)
	return UnFlate(b)
}

func Encode(input []byte) string {
	s := Flate(input)
	s = dsl.XorEncode(s, Key, 0)
	return dsl.Base64Encode(s)
}

func HasPingPriv() bool {
	if Win || Root {
		return true
	}
	return false
}

func sortIP(ips []string) []string {
	sort.Slice(ips, func(i, j int) bool {
		return ipcs.Ip2Int(ips[i]) < ipcs.Ip2Int(ips[j])
	})
	return ips
}
