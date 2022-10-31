package pkg

import (
	"bytes"
	"encoding/json"
	"fmt"
	. "github.com/chainreactors/files"
	"github.com/chainreactors/gogo/v2/pkg/utils"
	"github.com/chainreactors/ipcs"
	. "github.com/chainreactors/logs"
	"github.com/chainreactors/parsers"
	"os"
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

type IPMapResult map[string]*parsers.GOGOResult

func (imap IPMapResult) Get(port string) *parsers.GOGOResult {
	if result, ok := imap[port]; ok {
		return result
	}
	return &parsers.GOGOResult{}
}
func (imap IPMapResult) getWindowsInfo() windowsInfo {
	var wininfo = windowsInfo{}
	if imap.Get("445").Vulns != nil {
		wininfo.version = imap["445"].Title
	} else if imap.Get("445").Frameworks != nil {
		wininfo.version = imap["445"].Frameworks[0].Version
	} else if imap.Get("135").Frameworks != nil {
		wininfo.version = imap["135"].Frameworks[0].Version
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

func (imap IPMapResult) isWin() bool {
	for _, port := range winport {
		if _, ok := imap[port]; ok {
			return true
		}
	}
	return false
}

type ResultsData struct {
	*parsers.GOGOData
	Config Config
}

func (rd *ResultsData) groupByIP() map[string]IPMapResult {
	pfs := make(map[string]IPMapResult)
	//ipfs := make(map[string]ipformat)
	for _, result := range rd.Data {
		if pfs[result.Ip] == nil {
			pfs[result.Ip] = make(IPMapResult)
		}
		pfs[result.Ip][result.Port] = result
	}
	return pfs
}

func (rd *ResultsData) groupBySortedIP() (map[string]IPMapResult, []string) {
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
			if !(p.Port == "135 (oxid)" || p.Port == "137" || p.Port == "icmp") {
				if isColor {
					// 颜色输出
					s += fmt.Sprintf("\t%s://%s:%s\t%s\t%s\t%s\t%s [%s] %s %s %s\n",
						p.Protocol,
						ip,
						port,
						p.Midware,
						p.Language,
						Blue(p.Frameworks.ToString()),
						p.Host,
						//p.Hash,
						Yellow(p.Status),
						Blue(p.Title),
						Red(p.Vulns.ToString()),
						Blue(p.GetExtractStat()),
					)
				} else {
					s += fmt.Sprintf("\t%s://%s:%s\t%s\t%s\t%s\t%s [%s] %s %s %s\n",
						p.Protocol,
						ip,
						port,
						p.Midware,
						p.Language,
						p.Frameworks.ToString(),
						p.Host,
						//p.Cert,
						//p.Hash,
						p.Status,
						p.Title,
						p.Vulns.ToString(),
						p.GetExtractStat(),
					)
				}
			}
		}
	}
	return s
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

func autofixjson(content []byte) []byte {
	if string(content[len(content)-2:]) != "]}" {
		content = append(content, "]}"...)
		Log.Important("Task has not been completed,auto fix json")
		Log.Important("Task has not been completed,auto fix json")
		Log.Important("Task has not been completed,auto fix json")
	}
	return content
}

func LoadResult(content []byte) (*ResultsData, error) {
	// 自动修复未完成任务的json
	var err error

	var resultsdata *ResultsData
	err = json.Unmarshal(content, &resultsdata)
	if err != nil {
		return nil, err
	}
	return resultsdata, nil
}

type extractTmp struct {
	extracts Extracts
}

func LoadExtracts(content []byte) ([]*Extracts, error) {
	var err error
	var extractss []*Extracts

	for _, res := range bytes.Split(content, []byte{'\n'}) {
		var extracts *Extracts
		err = json.Unmarshal(res, &extracts)
		if err != nil {
			return nil, err
		}
		extractss = append(extractss, extracts)
	}
	return extractss, nil
}

type SmartData struct {
	Config Config   `json:"config"`
	Data   []string `json:"data"`
	IP     string   `json:"ip"`
}

func loadSmartResult(content []byte) (*SmartData, error) {
	var err error
	var smartdata *SmartData
	err = json.Unmarshal(content, &smartdata)
	if err != nil {
		return nil, err
	}
	return smartdata, nil
}

func LoadResultFile(file *os.File) interface{} {
	var data interface{}
	var err error
	content := DecryptFile(file, Key)

	content = bytes.TrimSpace(content) // 去除前后空格
	if bytes.Contains(content, []byte("\"smartb\",")) || bytes.Contains(content, []byte("\"smartc\",")) || bytes.Contains(content, []byte("\"ping\",")) {
		// 解析启发式扫描结果
		content = autofixjson(content)
		data, err = loadSmartResult(content)
	} else if bytes.Contains(content, []byte("\"scan\",")) {
		// 解析扫描结果
		content = autofixjson(content)
		data, err = LoadResult(content)
	} else if bytes.Contains(content, []byte("\"extract_result")) {
		// 解析extract结果
		data, err = LoadExtracts(content)
	} else if !IsJson(content) {
		// 解析按行分割的 ip:port:framework 输入
		var results parsers.GOGOResults
		for _, target := range utils.CleanSpiltCFLR(string(content)) {
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
					if !ipcs.IsIpv4(host) {
						if parsedIP, err := ipcs.ParseIP(host); err != nil {
							result = parsers.NewGOGOResult(parsedIP.String(), targetpair[1])
							result.Host = host
						}
					} else {
						result = parsers.NewGOGOResult(host, targetpair[1])
					}
				}

				if len(targetpair) == 3 {
					result.Frameworks = []*parsers.Framework{&parsers.Framework{Name: targetpair[2]}}
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
	} else {
		return content
	}
	if err != nil {
		fmt.Println("[-] json error, " + err.Error())
		return content
	}
	return data
}

func IsJson(content []byte) bool {
	var tmp interface{}
	err := json.Unmarshal(content, &tmp)
	if err != nil {
		return false
	}
	return true
}
