package core

import (
	"encoding/json"
	"fmt"
	"getitle/src/utils"
	"sort"
	"strings"
)

var first = true

type portformat struct {
	Port       string           `json:"p"`
	Hash       string           `json:"hs"`
	Stat       string           `json:"s"`
	Title      string           `json:"t"`
	Host       string           `json:"h"`
	Midware    string           `json:"m"`
	Language   string           `json:"l"`
	Frameworks utils.Frameworks `json:"f"`
	Vulns      utils.Vulns      `json:"v"`
	Protocol   string           `json:"r"`
}

func output(result *utils.Result, outType string) string {
	var out string

	switch outType {
	case "color", "c":
		out = colorOutput(result)
	case "json", "j":
		if FileHandle != nil {
			out = jsonFile(result)
		} else {
			out = jsonOutput(result)
		}
	//case "html":
	//	out = HtmlOutput(result)
	default:
		out = fullOutput(result)

	}
	return out

}

func colorOutput(result *utils.Result) string {
	s := fmt.Sprintf("[+] %s://%s:%s\t%s\t%s\t%s\t%s\t%s [%s] %s %s\n", result.Protocol, result.Ip, result.Port, result.Midware, result.Language, blue(result.Frameworks.ToString()), result.Host, result.Hash, yellow(result.HttpStat), blue(result.Title), red(result.Vulns.ToString()))
	return s
}

func fullOutput(result *utils.Result) string {
	s := fmt.Sprintf("[+] %s://%s:%s%s\t%s\t%s\t%s\t%s\t%s [%s] %s %s\n", result.Protocol, result.Ip, result.Port, result.Uri, result.Midware, result.Language, result.Frameworks.ToString(), result.Host, result.Hash, result.HttpStat, result.Title, result.Vulns.ToString())
	return s
}

func jsonOutput(result *utils.Result) string {
	jsons, err := json.Marshal(result)
	if err != nil {
		return ""
	}
	return string(jsons) + "\n"
}

func jsonFile(result *utils.Result) string {
	jsons, err := json.Marshal(result)
	if err != nil {
		return ""
	}
	if first {
		first = false
		return string(jsons)
	} else {
		return "," + string(jsons)
	}

}

func FormatOutput(filename string, outputfile string) {
	var outfunc func(s string)

	if outputfile != "" {
		fileHandle := initFileHandle(outputfile)
		defer fileHandle.Close()
		outfunc = func(s string) {
			_, _ = fileHandle.WriteString(s)
		}
	} else {
		outfunc = func(s string) {
			fmt.Print(s)
		}
	}
	resultsdata := utils.LoadResult(filename)
	// 输出配置信息
	configstr := fmt.Sprintf("[*] Scan Target: %s, Ports: %s, Mod: %s", resultsdata.Config.IP, resultsdata.Config.Ports, resultsdata.Config.Mod)
	if resultsdata.IP != "" {
		configstr += " Internet IP: " + resultsdata.IP
	}
	fmt.Println(configstr)

	pfs := make(map[string]map[string]portformat)
	//ipfs := make(map[string]ipformat)
	results := resultsdata.Data
	for _, result := range results {
		pf := portformat{
			Port:       result.Port,
			Stat:       result.HttpStat,
			Hash:       result.Hash,
			Title:      result.Title,
			Host:       result.Host,
			Midware:    result.Midware,
			Language:   result.Language,
			Frameworks: result.Frameworks,
			Vulns:      result.Vulns,
			Protocol:   result.Protocol,
		}
		if pfs[result.Ip] == nil {
			pfs[result.Ip] = make(map[string]portformat)
		}
		pfs[result.Ip][result.Port] = pf
	}

	// 排序
	var keys []int
	for ip, _ := range pfs {
		keys = append(keys, int(ip2int(ip)))
	}
	sort.Ints(keys)

	for _, ipi := range keys {
		ip := int2ip(uint(ipi))

		var hostname, network, netbiosstat string

		if _, k := pfs[ip]["135"]; k {
			hostname = pfs[ip]["135"].Host
			network = pfs[ip]["135"].Title
		}
		if _, k := pfs[ip]["137"]; k {
			hostname = pfs[ip]["137"].Host
			netbiosstat = pfs[ip]["137"].Stat
		}
		s := fmt.Sprintf("[+] %s %s %s %s\n", ip, hostname, netbiosstat, network)
		for pint, p := range pfs[ip] {
			// 跳过OXID与NetBois
			if !(p.Port == "135" || p.Port == "137" || p.Port == "icmp") {
				if Output == "c" {
					// 颜色输出
					s += fmt.Sprintf("\t%s://%s:%s\t%s\t%s\t%s\t%s\t%s [%s] %s %s", p.Protocol, ip, pint, p.Midware, p.Language, blue(p.Frameworks.ToString()), p.Host, p.Hash, yellow(p.Stat), blue(p.Title), red(p.Vulns.ToString()))
				} else {
					s += fmt.Sprintf("\t%s://%s:%s\t%s\t%s\t%s\t%s\t%s [%s] %s %s", p.Protocol, ip, pint, p.Midware, p.Language, p.Frameworks.ToString(), p.Host, p.Hash, p.Stat, p.Title, p.Vulns.ToString())
				}
				s += "\n"
			}
		}
		outfunc(s)
	}
	//fmt.Println(string(content))
}

func processLogln(s string) {
	s = s + " , " + utils.GetCurtime() + "\n"
	fmt.Print(s)
	if LogFileHandle != nil {
		LogDetach <- s
	}
}

func Banner() {
	//fmt.Println(
	//	"Usage of ./main:" +
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
	//		"\n     example:           ./main -ip 192.168.1.1 -p top2" +
	//		"\n     smart mod example: ./main -ip 192.168.1.1/8 -p top2 -m s",
	//)

}

func Printportconfig() {
	fmt.Println("当前已有端口配置: (根据端口类型分类)")
	for k, v := range utils.Namemap {
		fmt.Println("	", k, ": ", strings.Join(v, ","))
	}
	fmt.Println("当前已有端口配置: (根据服务分类)")
	for k, v := range utils.Tagmap {
		fmt.Println("	", k, ": ", strings.Join(v, ","))
	}
}

func PrintNucleiPoc() {
	fmt.Println("Nuclei Pocs")
	for k, v := range utils.TemplateMap {
		fmt.Println(k + ":")
		for _, t := range v {
			fmt.Println("\t" + t.Info.Name)
		}

	}
}

func PrintInterConfig() {
	fmt.Println("Auto internet smart scan config")
	fmt.Println("CIDR\t\tMOD\tPortProbe\tIpProbe")
	for k, v := range InterConfig {
		fmt.Printf("%s\t\t%s\n", k, strings.Join(v, "\t"))
	}
}

func red(s string) string {
	return "\033[1;31m" + s + "\033[0m"
}

func green(s string) string {
	return "\033[1;32m" + s + "\033[0m"
}

func yellow(s string) string {
	return "\033[4;33m" + s + "\033[0m"
}

func blue(s string) string {
	return "\033[1;34m" + s + "\033[0m"
}
