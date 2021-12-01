package utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strings"
)

var winport = []string{"445", "135", "137"}

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
	Config Config   `json:"config"`
	Data   []Result `json:"data"`
	IP     string   `json:"ip"`
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

func LoadResult(filename string) (*ResultsData, error) {
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	content = bytes.TrimSpace(content)
	// 自动修复未完成任务的json
	laststr := string(content[len(content)-2:])
	if laststr != "]}" {
		content = append(content, "]}"...)
		fmt.Println("[*] Task has not been completed,auto fix json")
		fmt.Println("[*] Task has not been completed,auto fix json")
		fmt.Println("[*] Task has not been completed,auto fix json")
	}

	var resultsdata *ResultsData
	err = json.Unmarshal(content, &resultsdata)
	if err != nil {
		fmt.Println("[-] json error, " + err.Error())
		return nil, err
	}

	return resultsdata, err
}
