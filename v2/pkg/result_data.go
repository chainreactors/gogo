package pkg

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/chainreactors/fingers/common"
	"io"
	"sort"
	"strings"

	"github.com/chainreactors/files"
	. "github.com/chainreactors/logs"
	"github.com/chainreactors/parsers"
	"github.com/chainreactors/utils"
)

func sortIP(ips []string) []string {
	sort.Slice(ips, func(i, j int) bool {
		if utils.ParseIP(ips[i]).Compare(utils.ParseIP(ips[j])) < 0 {
			return true
		} else {
			return false
		}
	})
	return ips
}

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

type PortMapResult map[string]*parsers.GOGOResult

func (imap PortMapResult) Get(port string) *parsers.GOGOResult {
	if result, ok := imap[port]; ok {
		return result
	}
	return &parsers.GOGOResult{}
}
func (imap PortMapResult) getWindowsInfo() windowsInfo {
	var wininfo = windowsInfo{}
	if imap.Get("445").Vulns != nil {
		wininfo.version = imap["445"].Title
	} else if imap.Get("445").Frameworks != nil {
		wininfo.version = imap["445"].GetFirstFramework().Version
	} else if imap.Get("135").Frameworks != nil {
		wininfo.version = imap["135"].GetFirstFramework().Version
	}

	if imap.Get("445").Host != "" {
		wininfo.hostname = imap["445"].Host
	} else if imap.Get("135").Host != "" {
		wininfo.hostname = imap["135"].Host
	} else {
		wininfo.hostname = imap.Get("137").Host
	}

	wininfo.netbiosstat = imap.Get("137").Status
	wininfo.networks = strings.Split(imap.Get("135 (oxid)").Title, ",")
	return wininfo
}

func (imap PortMapResult) isWin() bool {
	for _, port := range winport {
		if _, ok := imap[port]; ok {
			return true
		}
	}
	return false
}

type ResultsData struct {
	*parsers.GOGOData
}

func (rd *ResultsData) GetConfig() *Config {
	return &Config{GOGOConfig: rd.Config}
}

func (rd *ResultsData) groupByIP() map[string]PortMapResult {
	pfs := make(map[string]PortMapResult)
	for _, result := range rd.Data {
		if pfs[result.Ip] == nil {
			pfs[result.Ip] = make(PortMapResult)
		}
		pfs[result.Ip][result.Port] = result
	}
	return pfs
}

func (rd *ResultsData) groupBySortedIP() (map[string]PortMapResult, []string) {
	pfs := rd.groupByIP()
	ips := make([]string, len(pfs))
	var i = 0
	for ip, _ := range pfs {
		ips[i] = ip
		i++
	}
	return pfs, sortIP(ips)
}

func (rd *ResultsData) ToFormat(isColor bool) string {
	var s string

	pfs, ips := rd.groupBySortedIP()
	// 排序

	for _, ip := range ips {
		wininfo := pfs[ip].getWindowsInfo()
		s += fmt.Sprintf("[+] %s %s\n", ip, wininfo.toString())
		for port, p := range pfs[ip] {
			// 跳过OXID与NetBois
			if !(p.Port == "icmp") {
				if isColor {
					// 颜色输出
					url := fmt.Sprintf("%s://%s:%s", p.Protocol, ip, port)
					s += fmt.Sprintf("\t%s\t%s\t%s\t%s [%s] %s %s %s\n",
						GreenLine(url),
						p.Midware,
						p.FramesColorString(),
						Cyan(p.Host),
						Yellow(p.Status),
						Blue(p.Title),
						Red(p.Vulns.String()),
						Blue(p.GetExtractStat()),
					)
				} else {
					s += fmt.Sprintf("\t%s://%s:%s\t%s\t%s\t%s [%s] %s %s %s\n",
						p.Protocol,
						ip,
						port,
						p.Midware,
						p.Frameworks.String(),
						p.Host,
						p.Status,
						p.Title,
						p.Vulns.String(),
						p.GetExtractStat(),
					)
				}
			}
		}
	}
	return s
}

func (rd *ResultsData) ToExtracteds() string {
	var s strings.Builder
	for _, result := range rd.Data {
		if len(result.Extracteds) == 0 {
			continue
		}
		s.WriteString("[+] ")
		s.WriteString(result.GetTarget())
		s.WriteString("\n")
		for name, extract := range result.Extracteds {
			s.WriteString(fmt.Sprintf(" \t * %s \n\t\t", name))
			s.WriteString(strings.Join(extract, "\n\t\t") + "\n")
		}
	}
	return s.String()
}

func (rd *ResultsData) ToCobaltStrike() string {
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

func parseResult(content []byte) (parsers.GOGOResults, error) {
	var err error
	var results parsers.GOGOResults
	err = json.Unmarshal(content, &results)
	if err != nil {
		return nil, err
	}
	return results, nil
}

type SmartResult struct {
	Config *Config
	Data   map[string][]string `json:"data"`
}

func (sr *SmartResult) List() []string {
	var cidrs []string
	for _, c := range sr.Data {
		cidrs = append(cidrs, c...)
	}
	return cidrs
}

func parseSmartResult(content []byte) (map[string][]string, error) {
	var err error
	var smartdata map[string][]string
	err = json.Unmarshal(content, &smartdata)
	if err != nil {
		return nil, err
	}
	return smartdata, nil
}

func parseConfig(line []byte) (*Config, error) {
	var config *Config
	err := json.Unmarshal(line, &config)
	if err != nil {
		return nil, err
	}
	return config, nil
}

func LoadResultFile(file io.Reader) interface{} {
	var data interface{}
	var err error
	content := files.DecryptFile(file, files.Key)

	content = bytes.TrimSpace(content) // 去除前后空格
	lines := bytes.Split(content, []byte{0x0a})
	config, err := parseConfig(lines[0])
	if err != nil {
		// 解析按行输入的result格式
		// example: ip:port:[frame]   frame可选, 用作强行指定指纹, 留空自动忽略
		// 192.168.1.1:80
		// 192.168.1.2:8080:tomcat
		var results parsers.GOGOResults
		for _, target := range CleanSpiltCFLR(string(content)) {
			var result *parsers.GOGOResult
			if strings.Contains(target, ":") {
				if strings.Contains(target, "http") {
					if strings.HasPrefix(target, "http://") {
						target = strings.TrimLeft(target, "http://")
						if !strings.Contains(target, ":") {
							target = target + ":80"
						}
					} else if strings.HasPrefix(target, "https://") {
						target = strings.TrimLeft(target, "https://")
						if !strings.Contains(target, ":") {
							target = target + ":443"
						}
					}
				}

				targetpair := strings.Split(target, ":")
				host := targetpair[0]

				if len(targetpair) >= 2 {
					if parsedIP := utils.ParseIP(host); parsedIP != nil {
						result = parsers.NewGOGOResult(parsedIP.String(), targetpair[1])
						result.Host = host
					} else {
						result = parsers.NewGOGOResult(host, targetpair[1])
					}
				}

				if len(targetpair) == 3 {
					result.Frameworks = map[string]*common.Framework{targetpair[2]: common.NewFramework(targetpair[2], common.FrameFromDefault)}
				}
				if result != nil {
					results = append(results, result)
				}
			} else {
				//fmt.Printf("[-] format target: %s error\n\n", target)
				return content
			}
		}
		return results
	}

	// 解析dat文件
	var finished bool = true
	// 判断扫描是否结束
	if !bytes.Equal(lines[len(lines)-1], []byte("[\"done\"]")) {
		finished = false
		Log.Important("Task has not been completed,auto fix json")
		Log.Important("Task has not been completed,auto fix json")
		Log.Important("Task has not been completed,auto fix json")
	}

	// 删除最后一行
	var last int
	if finished {
		last = len(lines) - 1
	} else {
		last = len(lines)
	}
	var res bytes.Buffer
	switch config.JsonType {
	case "smartb", "smartc", "alive":
		sr := &SmartResult{
			Config: config,
		}
		for i, line := range lines {
			if i == 0 || (finished && i == last) {
				continue
			}
			lines[i] = line[1 : len(line)-1]
		}
		res.WriteString("{")
		res.Write(bytes.Join(lines[1:last], []byte{','}))
		res.WriteString("}")
		sr.Data, err = parseSmartResult(res.Bytes())
		if err != nil {
			fmt.Println("[-] json error, " + err.Error())
			return content
		}
		return sr
	case "scan":
		rd := &ResultsData{
			&parsers.GOGOData{
				Config: config.GOGOConfig,
			},
		}
		res.WriteString("[")
		res.Write(bytes.Join(lines[1:last], []byte{','}))
		res.WriteString("]")
		rd.Data, err = parseResult(res.Bytes())
		if err != nil {
			fmt.Println("[-] json error, " + err.Error())
			return content
		}
		return rd
	}
	return data
}
