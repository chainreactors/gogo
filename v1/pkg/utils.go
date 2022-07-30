package pkg

import (
	"fmt"
	"getitle/v1/pkg/dsl"
	"getitle/v1/pkg/utils"
	. "github.com/chainreactors/files"
	"github.com/chainreactors/ipcs"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
)

var (
	Win  = utils.IsWin()
	Root = utils.IsRoot()
	Key  = []byte{}
)

func GetHttpRaw(resp *http.Response) (string, string) {
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
		return raw, ""
	}
	raw += string(body)
	_ = resp.Body.Close()
	return raw, string(body)
}

func GetBody(resp *http.Response) []byte {
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return []byte{}
	}
	_ = resp.Body.Close()
	return body
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

func IsExist(filename string) bool {
	var exist = true
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		exist = false
	}
	return exist
}

func Open(filename string) *os.File {
	f, err := os.Open(filename)
	if err != nil {
		utils.Fatal("" + err.Error())
	}
	return f
}

func getAutoFilename(config *Config, outtype string) string {
	var basename string
	target := strings.Replace(config.GetTargetName(), "/", "_", -1)
	target = strings.Replace(target, ":", "", -1)
	target = strings.Replace(target, "\\", "_", -1)
	ports := strings.Replace(config.Ports, ",", "_", -1)
	basename = fmt.Sprintf("%s_%s_%s_%s", target, ports, config.Mod, outtype)
	return basename
}

var fileint = 1

func GetFilename(config *Config, format string, filepath, outtype string) string {
	var basename string
	var basepath string = filepath
	if filepath == "" {
		basepath = utils.GetExcPath()
	}

	if format == "auto" {
		basename = path.Join(basepath, "."+getAutoFilename(config, outtype)+".dat")
	} else if format == "hidden" {
		if Win {
			basename = path.Join(basepath, "App_1634884664021088500_EC1B25B2-9453-49EE-A1E2-112B4D539F5.dat")
		} else {
			basename = path.Join(basepath, ".systemd-private-701215aa8263408d8d44f4507834d77")
		}
	} else if format == "clear" {
		basename = path.Join(basepath, getAutoFilename(config, outtype)+".txt")
	} else {
		return ""
	}
	for IsExist(basename + utils.ToString(fileint)) {
		fileint++
	}
	return basename + utils.ToString(fileint)
}

func HasStdin() bool {
	stat, err := os.Stdin.Stat()
	if err != nil {
		return false
	}

	isPipedFromChrDev := (stat.Mode() & os.ModeCharDevice) == 0
	isPipedFromFIFO := (stat.Mode() & os.ModeNamedPipe) != 0

	return isPipedFromChrDev || isPipedFromFIFO
}
