package Scan

//
//import (
//	"main/src/Utils"
//	"io/ioutil"
//	"strings"
//)
//
//func NotFoundScan(target string, result Utils.Result) Utils.Result {
//
//	conn := Utils.HttpConn(Delay+2)
//	resp, err := conn.Get(target+"/fnotadjnq")
//	if err!=nil {
//		return result
//	}
//	bodyi,_ := ioutil.ReadAll(resp.Body)
//	body := string(bodyi)
//	if strings.Contains(body,"Apache Tomcat") {
//		result.Midware = "Tomcat"
//		//Utils.Match()
//		return result
//	}else if strings.Contains(body,"<faultactor>/fnotadjnq") {
//		result.Midware = "WebSphere"
//		return result
//	}else if strings.Contains(body,"aa") {
//		return  result
//	}
//
//
//	return result
//}
