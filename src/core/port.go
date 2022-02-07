package core

import (
	"getitle/src/pkg"
	"getitle/src/structutils"
	"strings"
)

func portHandler(portstring string) []string {
	var ports []string
	portstring = strings.TrimSpace(portstring)
	portstring = strings.Replace(portstring, "\r", "", -1)

	postslist := strings.Split(portstring, ",")
	for _, portname := range postslist {
		ports = append(ports, choiceports(portname)...)
	}
	ports = pkg.Ports2PortSlice(ports)
	ports = structutils.SliceUnique(ports)
	return ports
}

// 端口预设
func choiceports(portname string) []string {
	var ports []string
	if portname == "all" {
		for p := range pkg.PortMap {
			ports = append(ports, p)
		}
		return ports
	}

	if pkg.NameMap[portname] != nil {
		ports = append(ports, pkg.NameMap[portname]...)
		return ports
	} else if pkg.TagMap[portname] != nil {
		ports = append(ports, pkg.TagMap[portname]...)
		return ports
	} else {
		return []string{portname}
	}
}
