package pkg

import (
	"encoding/json"
	"fmt"
	. "github.com/chainreactors/files"
	"github.com/chainreactors/gogo/v2/pkg/dsl"
	"github.com/chainreactors/gogo/v2/pkg/utils"
	"github.com/chainreactors/ipcs"
	"github.com/chainreactors/logs"
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

func ValuesOutput(result *Result, outType string) string {
	outs := strings.Split(outType, ",")
	for i, out := range outs {
		outs[i] = result.Get(out)
	}
	return strings.Join(outs, "\t") + "\n"
}

func ColorOutput(result *Result) string {
	s := fmt.Sprintf("[+] %s\t%s\t%s\t%s\t%s [%s] %s %s\n", result.GetURL(), result.Midware, result.Language, logs.Blue(result.Frameworks.ToString()), result.Host, logs.Yellow(result.HttpStat), logs.Blue(result.Title), logs.Red(result.Vulns.ToString()))
	return s
}

func FullOutput(result *Result) string {
	s := fmt.Sprintf("[+] %s\t%s\t%s\t%s\t%s [%s] %s %s %s\n", result.GetURL(), result.Midware, result.Language, result.Frameworks.ToString(), result.Host, result.HttpStat, result.Title, result.Vulns.ToString(), result.Extracts.ToString())
	return s
}

func JsonOutput(result *Result) string {
	jsons, _ := json.Marshal(result)
	return string(jsons)
}
