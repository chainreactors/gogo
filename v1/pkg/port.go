package pkg

import (
	"getitle/src/pkg/utils"
	"strconv"
	"strings"
)

func PortsHandler(portstring string) []string {
	portstring = strings.TrimSpace(portstring)
	portstring = strings.Replace(portstring, "\r", "", -1)
	return portSliceHandler(strings.Split(portstring, ","))
}

func portSliceHandler(ports []string) []string {
	var portSlice []string
	for _, portname := range ports {
		portSlice = append(portSlice, choiceports(portname)...)
	}
	portSlice = parsePortsPreset(portSlice)
	portSlice = utils.SliceUnique(portSlice)
	return portSlice
}

func parsePortsPreset(ports []string) []string {
	var tmpports []string
	//生成端口列表 支持,和-
	for _, pr := range ports {
		if len(pr) == 0 {
			continue
		}
		pr = strings.TrimSpace(pr)
		if pr[0] == 45 {
			pr = "1" + pr
		}
		if pr[len(pr)-1] == 45 {
			pr = pr + "65535"
		}
		tmpports = append(tmpports, port2PortSlice(pr)...)
	}
	return tmpports
}

func port2PortSlice(port string) []string {
	var tmpports []string
	if strings.Contains(port, "-") {
		sf := strings.Split(port, "-")
		start, _ := strconv.Atoi(sf[0])
		fin, _ := strconv.Atoi(sf[1])
		for port := start; port <= fin; port++ {
			tmpports = append(tmpports, strconv.Itoa(port))
		}
	} else {
		tmpports = append(tmpports, port)
	}
	return tmpports
}

// 端口预设
func choiceports(portname string) []string {
	var ports []string
	if portname == "all" {
		for p := range PortMap {
			ports = append(ports, p)
		}
		return ports
	}

	if NameMap[portname] != nil {
		ports = append(ports, NameMap[portname]...)
		return ports
	} else if TagMap[portname] != nil {
		ports = append(ports, TagMap[portname]...)
		return ports
	} else {
		return []string{portname}
	}
}
