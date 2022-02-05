package core

import (
	"getitle/src/structutils"
	"getitle/src/utils"
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
	ports = utils.Ports2PortSlice(ports)
	ports = structutils.SliceUnique(ports)
	return ports
}

// 端口预设
func choiceports(portname string) []string {
	var ports []string
	if portname == "all" {
		for p := range utils.PortMap {
			ports = append(ports, p)
		}
		return ports
	}

	if utils.NameMap[portname] != nil {
		ports = append(ports, utils.NameMap[portname]...)
		return ports
	} else if utils.TagMap[portname] != nil {
		ports = append(ports, utils.TagMap[portname]...)
		return ports
	} else {
		return []string{portname}
	}
}
