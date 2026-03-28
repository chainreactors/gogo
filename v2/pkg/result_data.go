package pkg

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/chainreactors/fingers/common"
	"github.com/chainreactors/utils/fileutils"
	"io"
	"sort"
	"strings"

	. "github.com/chainreactors/logs"
	"github.com/chainreactors/parsers"
	"github.com/chainreactors/utils"
)

type sortableIP struct {
	raw    string
	parsed *utils.IP
}

func sortIP(ips []string) []string {
	parsedIPs := make([]sortableIP, len(ips))
	for i, ip := range ips {
		parsedIPs[i] = sortableIP{
			raw:    ip,
			parsed: utils.ParseIP(ip),
		}
	}

	sort.Slice(parsedIPs, func(i, j int) bool {
		left := parsedIPs[i].parsed
		right := parsedIPs[j].parsed

		switch {
		case left == nil && right == nil:
			return parsedIPs[i].raw < parsedIPs[j].raw
		case left == nil:
			return false
		case right == nil:
			return true
		default:
			return left.Compare(right) < 0
		}
	})

	for i := range parsedIPs {
		ips[i] = parsedIPs[i].raw
	}
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
	pfs := make(map[string]PortMapResult, len(rd.Data))
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
	pfs, ips := rd.groupBySortedIP()
	var s strings.Builder
	s.Grow(len(rd.Data) * 192)

	for _, ip := range ips {
		imap := pfs[ip]
		wininfo := imap.getWindowsInfo()
		s.WriteString("[+] ")
		s.WriteString(ip)
		s.WriteByte(' ')
		s.WriteString(wininfo.toString())
		s.WriteByte('\n')

		ports := make([]string, 0, len(imap))
		for port := range imap {
			ports = append(ports, port)
		}
		sort.Strings(ports)

		for _, port := range ports {
			p := imap[port]
			if p.Port == "icmp" {
				continue
			}

			if isColor {
				writeColorResultLine(&s, p, ip, port)
			} else {
				writePlainResultLine(&s, p, ip, port)
			}
		}
	}
	return s.String()
}

func appendBaseURL(builder *strings.Builder, protocol, ip, port string) {
	builder.WriteString(protocol)
	builder.WriteString("://")
	builder.WriteString(ip)
	builder.WriteByte(':')
	builder.WriteString(port)
}

func writePlainResultLine(builder *strings.Builder, result *parsers.GOGOResult, ip, port string) {
	builder.WriteByte('\t')
	appendBaseURL(builder, result.Protocol, ip, port)
	builder.WriteByte('\t')
	builder.WriteString(result.Midware)
	builder.WriteByte('\t')
	builder.WriteString(result.Frameworks.String())
	builder.WriteByte('\t')
	builder.WriteString(result.Host)
	builder.WriteString(" [")
	builder.WriteString(result.Status)
	builder.WriteString("] ")
	builder.WriteString(result.Title)
	builder.WriteByte(' ')
	builder.WriteString(result.Vulns.String())
	builder.WriteByte(' ')
	builder.WriteString(result.GetExtractStat())
	builder.WriteByte('\n')
}

func writeColorResultLine(builder *strings.Builder, result *parsers.GOGOResult, ip, port string) {
	var url strings.Builder
	url.Grow(len(result.Protocol) + len(ip) + len(port) + 4)
	appendBaseURL(&url, result.Protocol, ip, port)

	builder.WriteByte('\t')
	builder.WriteString(GreenLine(url.String()))
	builder.WriteByte('\t')
	builder.WriteString(result.Midware)
	builder.WriteByte('\t')
	builder.WriteString(result.FramesColorString())
	builder.WriteByte('\t')
	builder.WriteString(Cyan(result.Host))
	builder.WriteString(" [")
	builder.WriteString(Yellow(result.Status))
	builder.WriteString("] ")
	builder.WriteString(Blue(result.Title))
	builder.WriteByte(' ')
	builder.WriteString(Red(result.Vulns.String()))
	builder.WriteByte(' ')
	builder.WriteString(Blue(result.GetExtractStat()))
	builder.WriteByte('\n')
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
	content := fileutils.DecryptFile(file, fileutils.Key)
	content = bytes.TrimSpace(content)

	// 分割所有行
	lines := bytes.Split(content, []byte{'\n'})
	if len(lines) == 0 {
		return nil
	}

	var results []interface{}
	currentSegment := [][]byte{}

	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}

		// 检查是否是新的配置段开始
		if bytes.HasPrefix(line, []byte{'{'}) && bytes.Contains(line, []byte(`"json_type"`)) {
			// 处理已收集的段
			if len(currentSegment) > 0 {
				if result := parseSegment(currentSegment); result != nil {
					results = append(results, result)
				}
			}
			currentSegment = [][]byte{line}
		} else {
			currentSegment = append(currentSegment, line)
		}
	}

	// 处理最后一个段
	if len(currentSegment) > 0 {
		if result := parseSegment(currentSegment); result != nil {
			results = append(results, result)
		}
	}

	// 根据结果数量返回适当的值
	switch len(results) {
	case 0:
		return nil
	case 1:
		return results[0]
	default:
		var result *ResultsData
		for _, r := range results {
			if data, ok := r.(*ResultsData); ok {
				if data.Config != nil {
					result = data
				}
				if data.Data != nil {
					result.Data = append(data.Data, r.(*ResultsData).Data...)
				}
			}
		}
		return result
	}
}

func parseSegment(segment [][]byte) interface{} {
	if len(segment) == 0 {
		return nil
	}

	// 解析配置
	config, err := parseConfig(segment[0])
	if err != nil {
		return nil
	}

	// 检查是否以 done 结尾
	var dataLines [][]byte
	if bytes.Equal(segment[len(segment)-1], []byte(`["done"]`)) {
		dataLines = segment[1 : len(segment)-1]
	} else {
		dataLines = segment[1:]
	}

	// 根据配置类型处理数据
	switch config.JsonType {
	case "smartb", "smartc", "alive":
		return parseSmartResultData(config, dataLines)
	case "scan":
		return parseScanResultData(config, dataLines)
	default:
		return nil
	}
}

func parseSmartResultData(config *Config, lines [][]byte) *SmartResult {
	data := make(map[string][]string)
	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) == 0 || bytes.Equal(line, []byte(`["done"]`)) {
			continue
		}

		var chunk map[string][]string
		if err := json.Unmarshal(line, &chunk); err != nil {
			fmt.Println("[-] json error, " + err.Error())
			return nil
		}
		for k, v := range chunk {
			data[k] = v
		}
	}

	return &SmartResult{Config: config, Data: data}
}

func parseScanResultData(config *Config, lines [][]byte) *ResultsData {
	var data parsers.GOGOResults
	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) == 0 || bytes.Equal(line, []byte(`["done"]`)) {
			continue
		}

		var result parsers.GOGOResult
		if err := json.Unmarshal(line, &result); err != nil {
			fmt.Println("[-] json error, " + err.Error())
			return nil
		}
		data = append(data, &result)
	}

	return &ResultsData{&parsers.GOGOData{
		Config: config.GOGOConfig,
		Data:   data,
	}}
}

func parseLegacyFormat(content []byte) interface{} {
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
			return content
		}
	}
	return results
}
