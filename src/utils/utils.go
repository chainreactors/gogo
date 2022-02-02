package utils

import (
	"bytes"
	"compress/flate"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/twmb/murmur3"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

//获取当前时间
func GetCurtime() string {
	curtime := time.Now().Format("2006-01-02 15:04.05")
	return curtime
}

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
		fmt.Println("[-] regexp string error: " + s + " , " + err.Error())
		os.Exit(0)
	}
	return reg
}

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

//var flatedict = `{"i":"`+`","p":"`+`","u":"`+`","o":"`+`","h":"`+`","t":"`+`","m":"` + `","s":"` + `","l":"` + `","f":` + `null` + `","v":` + `"r":"`
var flatedict = `,":`

func Flate(input []byte) []byte {
	var bf = bytes.NewBuffer([]byte{})
	var flater, _ = flate.NewWriterDict(bf, flate.BestCompression, []byte(flatedict))
	defer flater.Close()
	if _, err := flater.Write(input); err != nil {
		println(err.Error())
		return []byte{}
	}
	if err := flater.Flush(); err != nil {
		println(err.Error())
		return []byte{}
	}
	return bf.Bytes()
}

func UnFlate(input []byte) []byte {
	rdata := bytes.NewReader(input)
	r := flate.NewReaderDict(rdata, []byte(flatedict))
	s, _ := ioutil.ReadAll(r)
	return s
}

func Decode(input string) []byte {
	b := Base64Decode(input)
	return UnFlate(b)
}

func Encode(input []byte) string {
	s := Flate(input)
	return Base64Encode(s)
}

func Base64Decode(s string) []byte {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		println(err.Error())
		os.Exit(0)
	}
	return data
}

func Base64Encode(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func HasPingPriv() bool {
	if Win || Root {
		return true
	}
	return false
}
