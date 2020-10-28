package Scan

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



//socket进行对网站的连接
func SocketHttp(target string) string {
	//fmt.Println(ip)
	var result string
	//socket tcp连接,超时时间
	conn, err := net.DialTimeout("tcp", target, Delay* time.Second)
	if err != nil {

		//fmt.Println(err)
		return ""
	}
	alivesum++
	err = conn.SetReadDeadline(time.Now().Add(Delay * time.Second))


	//发送内容
	data :=[]byte("GET / HTTP/1.1\r\nHost: " + target + "\r\n\r\n")
	content := string(SocketSend(conn,data))
	err = conn.Close()
	if err != nil {
		return ""
	}

	//获取状态码
	status := GetStatusCode(content)

	//如果是400可能是因为没有用https
	if status == "400" || strings.HasPrefix(status,"3") {
		result = SystemHttp(target,status)
		return result
	}

	//正则匹配title


	return GetTitle(content,target)


}

//使用封装好了http
func SystemHttp(target string,status string) string {
	if status == "400" {
		target = "https://" + target
	} else{
		target = "Scan://" + target
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	c := &http.Client{
		Transport: tr,
		Timeout:   Delay * time.Second,
	}
	resp, err := c.Get(target)

	if err != nil {
		return ""
	}
	alivesum++
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
	content = Encode(content)
	r, _ := regexp.Compile("(?i)<title>(.*)</title>")

	res := r.FindStringSubmatch(content)

	if len(res) < 2 {
		result = "[+] " + target + "  open ---------" + string([]byte(content)[:13])
		//fmt.Println(result)
	} else {
		result = "[+] " + target + "  open ---------" + res[1]
	}
	titlesum++
	return result
}