package Utils

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

//func Ip2int(ipmask string) uint {
//	Ip := strings.Split(ipmask, "/")
//	s2ip := net.ParseIP(Ip[0]).To4()
//	return uint(s2ip[3]) | uint(s2ip[2])<<8 | uint(s2ip[1])<<16 | uint(s2ip[0])<<24
//}
//
//func Int2ip(ipint uint) string {
//	ip := make(net.IP, net.IPv4len)
//	ip[0] = byte(ipint >> 24)
//	ip[1] = byte(ipint >> 16)
//	ip[2] = byte(ipint >> 8)
//	ip[3] = byte(ipint)
//	return ip.String()
//}

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

func Encode(s string) string {
	s = strings.Replace(s, "\r", "%13", -1)
	s = strings.Replace(s, "\n", "%10", -1)
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
		return res[1]
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

func SliceContains(s []string, e string) bool {
	for _, v := range s {
		if v == e {
			return true
		}
	}
	return false
}

func Ports2PortSlice(ports []string) []string {
	var tmpports []string
	//生成端口列表 支持,和-
	for _, pr := range ports {
		tmpports = append(tmpports, port2PortSlice(pr)...)
	}
	return tmpports
}

func port2PortSlice(port string) []string {
	var tmpports []string
	if strings.Contains(port, "-") {
		sf := strings.Split(port, "-")
		start, _ := strconv.Atoi(sf[0])
		fin, _ := strconv.Atoi(sf[1])
		for port := start; port <= fin; port++ {
			tmpports = append(tmpports, strconv.Itoa(port))
		}
	} else {
		tmpports = append(tmpports, port)
	}
	return tmpports
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
