package scan

//
//import (
//	"main/src/utils"
//	"io/ioutil"
//	"strings"
//)
//
//func NotFoundScan(target string, result utils.result) utils.result {
//
//	conn := utils.HttpConn(Delay+2)
//	resp, err := conn.Get(target+"/fnotadjnq")
//	if err!=nil {
//		return result
//	}
//	bodyi,_ := ioutil.ReadAll(resp.Body)
//	body := string(bodyi)
//	if strings.Contains(body,"Apache Tomcat") {
//		result.Midware = "Tomcat"
//		//utils.Match()
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
