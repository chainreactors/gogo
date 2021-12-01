package utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
)

type ResultsData struct {
	Config Config   `json:"config"`
	Data   []Result `json:"data"`
	IP     string   `json:"ip"`
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

	pfs := make(map[string]map[string]Result)
	//ipfs := make(map[string]ipformat)
	results := rd.Data
	for _, result := range results {
		if pfs[result.Ip] == nil {
			pfs[result.Ip] = make(map[string]Result)
		}
		pfs[result.Ip][result.Port] = result
	}

	// 排序
	var ips []string
	for ip, _ := range pfs {
		ips = append(ips, ip)
	}

	for _, ip := range sort_ip(ips) {
		var hostname, networks, netbiosstat, winver string

		if len(pfs[ip]["445"].Vulns) != 0 {
			winver = pfs[ip]["445"].Title
		} else if pfs[ip]["445"].Frameworks != nil {
			winver = pfs[ip]["445"].Frameworks[0].Version
		} else if pfs[ip]["135"].Frameworks != nil {
			winver = pfs[ip]["135"].Frameworks[0].Version
		}

		if pfs[ip]["445"].Host != "" {
			hostname = pfs[ip]["445"].Host
		} else if pfs[ip]["135"].Host != "" {
			hostname = pfs[ip]["445"].Host
		} else {
			hostname = pfs[ip]["137"].Host
		}

		netbiosstat = pfs[ip]["137"].HttpStat
		networks = pfs[ip]["135 (oxid)"].Title
		s += fmt.Sprintf("[+] %s %s %s %s %s\n", ip, winver, hostname, netbiosstat, networks)
		for port, p := range pfs[ip] {
			// 跳过OXID与NetBois
			if !(p.Port == "135 (oxid)" || p.Port == "137" || p.Port == "icmp") {
				if isColor {
					// 颜色输出
					s += fmt.Sprintf("\t%s://%s:%s\t%s\t%s\t%s\t%s\t%s [%s] %s %s", p.Protocol, ip, port, p.Midware, p.Language, Blue(p.Frameworks.ToString()), p.Host, p.Hash, Yellow(p.HttpStat), Blue(p.Title), Red(p.Vulns.ToString()))
				} else {
					s += fmt.Sprintf("\t%s://%s:%s\t%s\t%s\t%s\t%s\t%s [%s] %s %s", p.Protocol, ip, port, p.Midware, p.Language, p.Frameworks.ToString(), p.Host, p.Hash, p.HttpStat, p.Title, p.Vulns.ToString())
				}
				s += "\n"
			}
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
