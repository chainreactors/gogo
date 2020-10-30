package moudle

import (
	"encoding/json"
	"fmt"
	"getitle/src/Utils"
	"strings"
)

func output(result Utils.Result) {
	var out string
	if strings.Contains(Outputforamt, "clean") {
		out += cleanOutput(result)
	}
	if strings.Contains(Outputforamt, "full") {
		out += fullOutput(result)
	}
	if strings.Contains(Outputforamt, "json") {
		out += jsonOutput(result)
	}
	fmt.Print(out)

}

func cleanOutput(result Utils.Result) string {
	s := fmt.Sprintf("[+] %s://%s:%s\tOPEN\t%s\t\n", result.Protocol, result.Ip, result.Port, result.Title)
	s += vulnOutput(result)
	return s
}

func fullOutput(result Utils.Result) string {
	s := fmt.Sprintf("[+] %s://%s:%s\tOPEN\t%s\t%s\t%s\t%s\t\n", result.Protocol, result.Ip, result.Port, result.Midware, result.Language, result.Framework, result.Title)
	s += vulnOutput(result)
	return s
}

func jsonOutput(result Utils.Result) string {
	jsons, err := json.Marshal(result)
	if err != nil {
		return ""
	}
	return string(jsons) + "\n"
}

func JsonReturn(result Utils.Result) string {
	jsons, err := json.Marshal(result)
	//if err == nil {
	//	return jsons
	//}
	//return []byte("\x00")
	if err == nil {
		return string(jsons)
	}
	return ""
}

func vulnOutput(result Utils.Result) string {
	if result.Vuln != "" {
		return fmt.Sprint("Find Vuln:" + result.Vuln)
	}
	return ""
}

func Banner() {
	//fmt.Println(
	//	"Usage of ./getitle:" +
	//		"\n  -d int			超时,默认2s (default 2)  " +
	//		"\n  -ip string		IP地址 like 192.168.1.1/24" +
	//		"\n  -m string        扫描模式：default or s(smart)" +
	//		"\n  -p string        ports (default \"top1\")" +
	//		"\n     ports preset:   top1(default) 80,81,88,443,8080,7001,9001,8081,8000,8443" +
	//		"\n                     top2 80-90,443,7000-7009,9000-9009,8080-8090,8000-8009,8443,7080,8070,9080,8888,7777,9999,9090,800,801,808,5555,10080" +
	//		"\n                     db 3306,1433,1521,5432,6379,11211,27017" +
	//		"\n                     rce 1090,1098,1099,4444,11099,47001,47002,10999,45000,45001,8686,9012,50500,4848,11111,4445,4786,5555,5556" +
	//		"\n                     win 53,88,135,139,389,445,3389,5985" +
	//		"\n                     brute 21,22,389,445,1433,1521,3306,3389,5901,5432,6379,11211,27017" +
	//		"\n                     all 21,22,23,25,53,69,80,81-89,110,135,139,143,443,445,465,993,995,1080,1158,1433,1521,1863,2100,3128,3306,3389,7001,8080,8081-8088,8888,9080,9090,5900,1090,1099,7002,8161,9043,50000,50070,389,5432,5984,9200,11211,27017,161,873,1833,2049,2181,2375,6000,6666,6667,7777,6868,9000,9001,12345,5632,9081,3700,4848,1352,8069,9300" +
	//		"\n  -t int        threads (default 4000)" +
	//		"\n  -o string     输出格式:clean,full(default) or json\n" +
	//		"\n     example:           ./getitle -ip 192.168.1.1 -p top2" +
	//		"\n     smart mod example: ./getitle -ip 192.168.1.1/8 -p top2 -m s",
	//)

}
