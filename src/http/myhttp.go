package http

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var alivesum, titlesum int

func Dispatch(target string,delay int) string{
	var tmp []string
	var result string
	tmp = strings.Split(target, ":")
	switch tmp[1] {
	case "443","8443":
		result = SystemHttp(target,delay)
	default:
		result = SocketHttp(target,delay)
	}
	return result
}
//socket进行对网站的连接
func SocketHttp(target string, delay int) string {
	//fmt.Println(ip)
	var result string

	//socket tcp连接,超时时间
	conn, err := net.DialTimeout("tcp", target, time.Duration(delay)*time.Second)

	if err != nil {

		//fmt.Println(err)
		return ""
	}

	//发送内容
	_, err = conn.Write([]byte("GET / HTTP/1.1\r\nHost: " + target + "\r\n\r\n"))

	if err != nil {
		return ""
	}

	//读取时间2秒超时
	err = conn.SetReadDeadline(time.Now().Add(time.Duration(delay) * time.Second))

	if err != nil {
		return ""
	}

	//最多只读8192位,一般来说有title就肯定已经有了
	reply := make([]byte, 8192)
	_, err = conn.Read(reply)

	if err != nil {
		return ""
	}

	err = conn.Close()
	if err != nil {
		return ""
	}
	content := string(reply)

	//获取状态码
	status := GetStatusCode(content)

	//如果是400可能是因为没有用https
	if status == "400" || strings.HasPrefix(status,"3") {
		result = SystemHttp(target,delay)
		return result
	}

	//正则匹配title

	titlesum++

	return GetTitle(content,target)


}

//使用封装好了http
func SystemHttp(target string,delay int) string {
	target = "https://" + target

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	c := &http.Client{
		Transport: tr,
		Timeout:  time.Duration(delay) * time.Second,
	}
	resp, err := c.Get(target)

	if err != nil {
		return ""
	}

	reply, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()

	content := string(reply)

	if err != nil {

		return ""
	}

	return GetTitle(content,target)
}

func GetStatusCode(html string) string {
	http1 := strings.Split(html, "\n")[0]
	statusC := strings.Split(http1, " ")
	if len(statusC) > 2 {
		statusCode := statusC[1]
		return statusCode
	}

	return ""
}

func OutputAliveSum() {
	fmt.Println("AliveSum: " + strconv.Itoa(alivesum))
}

func OutputTitleSum() {
	fmt.Println("TitleSum: " + strconv.Itoa(titlesum))
}


func GetTitle(content string,target string)string{
	var result string

	r, _ := regexp.Compile("<title>(.*)</title>")

	res := r.FindStringSubmatch(content)

	if len(res) < 2 {
		result = "[+]" + target + "  open ---------" + string([]byte(content)[:13])
		//fmt.Println(result)
	} else {
		result = "[+]" + target + "  open ---------" + res[1]
	}
	alivesum++
	return result
}