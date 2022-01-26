package utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

var winport = []string{"445", "135", "137"}
var zombiemap = map[string]string{
	"mariadb":   "MYSQL",
	"mysql":     "MYSQL",
	"rdp":       "RDP",
	"oracle":    "ORACLE",
	"sqlserver": "MSSQL",
	"mssql":     "MSSQL",
	"smb":       "SMB",
	"redis":     "REDIS",
	"vnc":       "VNC",
	//"elasticsearch": "ELASTICSEARCH",
	"postgresql": "POSTGRESQL",
	"mongo":      "MONGO",
	"ssh":        "SSH",
	"ftp":        "FTP",
}

type windowsInfo struct {
	hostname    string
	version     string
	netbiosstat string
	networks    []string
}

func (wininfo windowsInfo) toString() string {
	return fmt.Sprintf("%s %s %s %s", wininfo.version, wininfo.hostname, wininfo.netbiosstat, strings.Join(wininfo.networks, ","))
}

type IPMapResult map[string]Result

func (imap IPMapResult) getWindowsInfo() windowsInfo {
	var wininfo = windowsInfo{}
	if len(imap["445"].Vulns) != 0 {
		wininfo.version = imap["445"].Title
	} else if imap["445"].Frameworks != nil {
		wininfo.version = imap["445"].Frameworks[0].Version
	} else if imap["135"].Frameworks != nil {
		wininfo.version = imap["135"].Frameworks[0].Version
	}

	if imap["445"].Host != "" {
		wininfo.hostname = imap["445"].Host
	} else if imap["135"].Host != "" {
		wininfo.hostname = imap["445"].Host
	} else {
		wininfo.hostname = imap["137"].Host
	}

	wininfo.netbiosstat = imap["137"].HttpStat
	wininfo.networks = strings.Split(imap["135 (oxid)"].Title, ",")
	return wininfo
}

func (imap IPMapResult) isWin() bool {
	for _, port := range winport {
		if _, ok := imap[port]; ok {
			return true
		}
	}
	return false
}

type ResultsData struct {
	Config Config  `json:"config"`
	Data   Results `json:"data"`
	IP     string  `json:"ip"`
}

func (rd ResultsData) groupByIP() map[string]IPMapResult {
	pfs := make(map[string]IPMapResult)
	//ipfs := make(map[string]ipformat)
	for _, result := range rd.Data {
		if pfs[result.Ip] == nil {
			pfs[result.Ip] = make(map[string]Result)
		}
		pfs[result.Ip][result.Port] = *result
	}
	return pfs
}

func (rd ResultsData) groupBySortedIP() (map[string]IPMapResult, []string) {
	pfs := rd.groupByIP()
	ips := make([]string, len(pfs))
	var i = 0
	for ip, _ := range pfs {
		ips[i] = ip
		i++
	}
	return pfs, sort_ip(ips)
}

func (rd ResultsData) ToConfig() string {
	// 输出配置信息
	var configstr string
	configstr = fmt.Sprintf("[*] Scan Target: %s, Ports: %s, Mod: %s \n", rd.Config.GetTargetName(), rd.Config.Ports, rd.Config.Mod)
	configstr += fmt.Sprintf("[*] Exploit: %s, Version level: %d \n", rd.Config.Exploit, rd.Config.VerisonLevel)
	if rd.IP != "" {
		configstr += fmt.Sprintf("[*] Internet IP: %s", rd.IP)
	}
	return configstr
}

func (rd ResultsData) ToValues(outType string) string {
	outs := strings.Split(outType, ",")
	outvalues := make([][]string, len(outs))
	ss := make([]string, len(rd.Data))
	for i, out := range outs {
		outvalues[i] = rd.Data.GetValues(out)
	}

	for i := 0; i < len(ss); i++ {
		for j := 0; j < len(outvalues); j++ {
			ss[i] += outvalues[j][i] + "\t"
		}
		strings.TrimSpace(ss[i])
	}

	return strings.Join(ss, "\n")
}

func (rd ResultsData) ToFormat(isColor bool) string {
	var s string

	pfs, ips := rd.groupBySortedIP()
	// 排序

	for _, ip := range ips {
		wininfo := pfs[ip].getWindowsInfo()
		s += fmt.Sprintf("[+] %s %s\n", ip, wininfo.toString())
		for port, p := range pfs[ip] {
			// 跳过OXID与NetBois
			if !(p.Port == "135 (oxid)" || p.Port == "137" || p.Port == "icmp") {
				if isColor {
					// 颜色输出
					s += fmt.Sprintf("\t%s://%s:%s\t%s\t%s\t%s\t%s\t%s [%s] %s %s\n", p.Protocol, ip, port, p.Midware, p.Language, Blue(p.Frameworks.ToString()), p.Host, p.Hash, Yellow(p.HttpStat), Blue(p.Title), Red(p.Vulns.ToString()))
				} else {
					s += fmt.Sprintf("\t%s://%s:%s\t%s\t%s\t%s\t%s\t%s [%s] %s %s\n", p.Protocol, ip, port, p.Midware, p.Language, p.Frameworks.ToString(), p.Host, p.Hash, p.HttpStat, p.Title, p.Vulns.ToString())
				}
			}
		}
	}
	return s
}

func (rd ResultsData) ToCobaltStrike() string {
	var s string
	pfs := rd.groupByIP()
	for ip, imap := range pfs {
		if imap.isWin() {
			wininfo := imap.getWindowsInfo()
			winver := strings.Split(wininfo.version, "_")

			ver := winver[0]
			var build string
			if len(winver) == 2 && len(winver[1]) > 2 {
				build = winver[1][1 : len(winver[1])-2]
			}
			note := fmt.Sprintf("%s %s", wininfo.netbiosstat, strings.Join(wininfo.networks, ","))
			s += fmt.Sprintf("%s||%s||%s||%s||%s\n", ip, strings.TrimSpace(wininfo.hostname), ver, build, note)
		}
	}
	return s
}

func (rd ResultsData) ToZombie() string {
	var filtedres Results

	for k, _ := range zombiemap {
		filtedres = append(filtedres, rd.Data.Filter("frameworks", k, "::")...)
	}
	zms := make([]zombiemeta, len(filtedres))

	for i, result := range filtedres {
		zms[i] = result.toZombie()
	}
	s, err := json.Marshal(zms)
	if err != nil {
		fmt.Println("[-] " + err.Error())
		os.Exit(0)
	}
	return string(s)
}

func autofixjson(content []byte) []byte {
	if string(content[len(content)-2:]) != "]}" {
		content = append(content, "]}"...)
		fmt.Println("[*] Task has not been completed,auto fix json")
		fmt.Println("[*] Task has not been completed,auto fix json")
		fmt.Println("[*] Task has not been completed,auto fix json")
	}
	return content
}

func LoadResult(content []byte) (ResultsData, error) {
	// 自动修复未完成任务的json
	var err error

	var resultsdata ResultsData
	err = json.Unmarshal(content, &resultsdata)
	if err != nil {
		return resultsdata, err
		//os.Exit(0)
	}
	return resultsdata, nil
}

type SmartData struct {
	Config Config   `json:"config"`
	Data   []string `json:"data"`
	IP     string   `json:"ip"`
}

func loadSmartResult(content []byte) (SmartData, error) {
	var err error
	var smartdata SmartData
	err = json.Unmarshal(content, &smartdata)
	if err != nil {
		return smartdata, err
	}
	return smartdata, nil
}

func LoadResultFile(file *os.File) interface{} {
	var data interface{}
	content, err := ioutil.ReadAll(file)
	if err != nil {
		os.Exit(0)
	}

	if isBase64(content) {
		// stdin输入二进制文件支持base64编码之后的. base64 result.txt|gt -F stdin
		// 如果直接输入解压缩之后的json文件,则跳过这个步骤
		content = Base64Decode(string(content))
	}
	if IsBin(content) {
		content = UnFlate(content)
	}

	content = bytes.TrimSpace(content) // 去除前后空格
	if bytes.Contains(content, []byte("\"smart\",")) || bytes.Contains(content, []byte("\"ping\",")) {
		content = autofixjson(content)
		data, err = loadSmartResult(content)
	} else if bytes.Contains(content, []byte("\"scan\",")) {
		content = autofixjson(content)
		data, err = LoadResult(content)
	} else {
		var results Results
		for _, target := range strings.Split(string(content), "\n") {
			if strings.Contains(target, ":") {
				targetpair := strings.Split(target, ":")
				results = append(results, NewResult(targetpair[0], targetpair[1]))
			} else {
				return content
			}
		}
		return results
	}
	if err != nil {
		fmt.Println("[-] json error, " + err.Error())
		return content
	}
	return data
}

func isClearResult(content []byte) bool {
	if bytes.Equal(content[0:9], []byte("{\"config\"")) {
		return true
	}
	return false
}

func isBase64(content []byte) bool {
	b64bytes := []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
	for _, i := range content {
		if !bytes.Contains(b64bytes, []byte{i}) {
			return false
		}
	}
	return true
}

func IsBin(content []byte) bool {
	for _, i := range content {
		if i < 9 {
			return true
		}
	}
	return false
}

func IsJson(content []byte) bool {
	var tmp interface{}
	err := json.Unmarshal(content, &tmp)
	if err != nil {
		return false
	}
	return true
}
