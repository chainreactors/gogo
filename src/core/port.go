package core

import (
	"getitle/src/utils"
	"strings"
)

func portHandler(portstring string) []string {
	var ports []string
	portstring = strings.Replace(portstring, "\r", "", -1)

	postslist := strings.Split(portstring, ",")
	for _, portname := range postslist {
		ports = append(ports, choiceports(portname)...)
	}
	ports = utils.Ports2PortSlice(ports)
	ports = utils.SliceUnique(ports)
	return ports
}

// 端口预设
func choiceports(portname string) []string {
	var ports []string
	if portname == "all" {
		for p := range utils.Portmap {
			ports = append(ports, p)
		}
		return ports
	}

	if utils.Namemap[portname] != nil {
		ports = append(ports, utils.Namemap[portname]...)
		return ports
	} else if utils.Tagmap[portname] != nil {
		ports = append(ports, utils.Tagmap[portname]...)
		return ports
	} else {
		return []string{portname}
	}
}
