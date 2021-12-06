package structutils

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/twmb/murmur3"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strconv"
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
	return body
}

func EncodeTitle(s string) string {
	if len(s) >= 13 {
		s = s[:13]
	}
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

func CompileMatch(reg regexp.Regexp, s string) (string, bool) {
	res := reg.FindStringSubmatch(s)
	if len(res) == 1 {
		return "", true
	} else if len(res) == 2 {
		return strings.TrimSpace(res[1]), true
	}
	return "", false
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

func CompileRegexp(s string) regexp.Regexp {
	reg, err := regexp.Compile(s)
	if err != nil {
		fmt.Println("[-] regexp string error: " + s)
		os.Exit(0)
	}
	return *reg
}

func ToString(data interface{}) string {
	switch s := data.(type) {
	case nil:
		return ""
	case string:
		return s
	case bool:
		return strconv.FormatBool(s)
	case float64:
		return strconv.FormatFloat(s, 'f', -1, 64)
	case float32:
		return strconv.FormatFloat(float64(s), 'f', -1, 32)
	case int:
		return strconv.Itoa(s)
	case int64:
		return strconv.FormatInt(s, 10)
	case int32:
		return strconv.Itoa(int(s))
	case int16:
		return strconv.FormatInt(int64(s), 10)
	case int8:
		return strconv.FormatInt(int64(s), 10)
	case uint:
		return strconv.FormatUint(uint64(s), 10)
	case uint64:
		return strconv.FormatUint(s, 10)
	case uint32:
		return strconv.FormatUint(uint64(s), 10)
	case uint16:
		return strconv.FormatUint(uint64(s), 10)
	case uint8:
		return strconv.FormatUint(uint64(s), 10)
	case []byte:
		return string(s)
	case fmt.Stringer:
		return s.String()
	case error:
		return s.Error()
	default:
		return fmt.Sprintf("%v", data)
	}
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

func Zip(input string) string {
	var bf = bytes.NewBuffer([]byte{})
	var flater, _ = flate.NewWriterDict(bf, flate.BestCompression, []byte(flatedict))
	defer flater.Close()
	if _, err := flater.Write([]byte(input)); err != nil {
		println(err.Error())
		return ""
	}
	if err := flater.Flush(); err != nil {
		println(err.Error())
		return ""
	}
	return bf.String()
}

func Unzip(input string) []byte {
	data := Base64Decode(input)
	rdata := bytes.NewReader(data)
	r, _ := gzip.NewReader(rdata)
	s, _ := ioutil.ReadAll(r)
	return s
}

func UnFlate(input []byte) []byte {
	//data := Base64Decode(input)
	rdata := bytes.NewReader(input)
	r := flate.NewReaderDict(rdata, []byte(flatedict))
	s, _ := ioutil.ReadAll(r)
	return s
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
