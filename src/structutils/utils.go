package structutils

import (
	"bytes"
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
	h := strconv.Itoa(time.Now().Hour())
	m := strconv.Itoa(time.Now().Minute())
	s := strconv.Itoa(time.Now().Second())

	curtime := h + ":" + m + ":" + s
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
	s = strings.Replace(s, "\r", "\\0x13", -1)
	s = strings.Replace(s, "\n", "\\0x10", -1)
	return s
}

func Match(regexpstr string, s string) string {
	reg, err := regexp.Compile(regexpstr)
	if err != nil {
		return ""
	}
	res := reg.FindStringSubmatch(s)
	if len(res) == 1 {
		return "matched"
	} else if len(res) == 2 {
		return res[1]
	}
	return ""
}

func CompileMatch(reg regexp.Regexp, s string) string {
	res := reg.FindStringSubmatch(s)
	if len(res) == 1 {
		return "matched"
	} else if len(res) == 2 {
		return strings.TrimSpace(res[1])
	}
	return ""
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

// MergeMaps merges two maps into a New map
func MergeMaps(m1, m2 map[string]interface{}) map[string]interface{} {
	m := make(map[string]interface{}, len(m1)+len(m2))
	for k, v := range m1 {
		m[k] = v
	}
	for k, v := range m2 {
		m[k] = v
	}
	return m
}

func SliceContains(s []string, e string) bool {
	for _, v := range s {
		if v == e {
			return true
		}
	}
	return false
}

//切片去重
func SliceUnique(ss []string) []string {
	res := make([]string, 0, len(ss))
	temp := map[string]struct{}{}
	for _, item := range ss {
		if _, ok := temp[item]; !ok {
			temp[item] = struct{}{}
			res = append(res, item)
		}
	}
	return res
}

func Str2uintlist(s string) []uint {
	var ipps []uint
	ss := strings.Split(s, ",")
	for _, ipp := range ss {
		intipp, _ := strconv.Atoi(ipp)
		ipps = append(ipps, uint(intipp))
	}
	return ipps
}

func UintSlice2str(i []uint) []string {
	s := make([]string, len(i))
	for k, v := range i {
		s[k] = ToString(v)
	}
	return s
}

func MaptoString(m map[string]interface{}) string {
	if m == nil || len(m) == 0 {
		return ""
	}
	var s string
	for k, v := range m {
		s += fmt.Sprintf(" %s:%s ", k, ToString(v))
	}
	return s
}

func ToStringMap(i interface{}) map[string]interface{} {
	var m = map[string]interface{}{}

	switch v := i.(type) {
	case map[interface{}]interface{}:
		for k, val := range v {
			m[ToString(k)] = val
		}
		return m
	case map[string]interface{}:
		return v
	default:
		return nil
	}
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
