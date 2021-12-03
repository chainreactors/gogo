package utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"getitle/src/structutils"
	"io/ioutil"
	"os"
	"strings"
)

var winport = []string{"445", "135", "137"}
var zombiemap = map[string]string{
	"mariadb":             "MYSQL",
	"mysql":               "MYSQL",
	"microsoft rdp":       "RDP",
	"oracle database":     "ORACLE",
	"microsoft sqlserver": "MSSQL",
	"mssql":               "MSSQL",
	"smb":                 "SMB",
	"redis":               "REDIS",
	"vnc":                 "VNC",
	//"elasticsearch": "ELASTICSEARCH",
	"postgreSQL": "POSTGRESQL",
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
		pfs[result.Ip][result.Port] = result
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
	configstr = fmt.Sprintf("[*] Scan Target: %s, Ports: %s, Mod: %s \n", rd.Config.GetTarget(), rd.Config.Ports, rd.Config.Mod)
	configstr += fmt.Sprintf("[*] Exploit: %s, Version level: %d \n", rd.Config.Exploit, rd.Config.VerisonLevel)
	if rd.IP != "" {
		configstr += fmt.Sprintf("[*] Internet IP: %s", rd.IP)
	}
	return configstr
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

func (rd ResultsData) GetValue(key string) string {
	values := make([]string, len(rd.Data))
	for i, result := range rd.Data {
		values[i] = result.Get(key)
	}
	return strings.Join(values, "\n")
}

func (rd ResultsData) ToCobaltStrike() string {
	var s string
	pfs := rd.groupByIP()
	for ip, imap := range pfs {
		if imap.isWin() {
			s += fmt.Sprintf("%s %s", ip, imap.getWindowsInfo().toString())
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

func LoadResultFile(filename string) interface{} {
	var data interface{}
	content, err := ioutil.ReadFile(filename)
	if !bytes.Equal(content[0:10], []byte("{\"config\"")) {
		content = structutils.UnFlate(content)
	}

	if err != nil {
		os.Exit(0)
	}
	content = bytes.TrimSpace(content)
	content = autofixjson(content)
	if bytes.Contains(content, []byte("'\"json_type\":\"smart\"'")) {
		data, err = loadSmartResult(content)
	} else {
		data, err = LoadResult(content)
	}
	if err != nil {
		fmt.Println("[-] json error, " + err.Error())
		os.Exit(0)
	}
	return data
}
