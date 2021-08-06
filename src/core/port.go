package core

import (
	"fmt"
	"getitle/src/Utils"
	"strings"
)

func PortHandler(portstring string) []string {
	var ports []string
	portstring = strings.Replace(portstring, "\r", "", -1)

	postslist := strings.Split(portstring, ",")
	for _, portname := range postslist {
		ports = append(ports, choiceports(portname)...)
	}
	ports = Utils.Ports2PortSlice(ports)
	ports = Utils.SliceUnique(ports)
	return ports
}

// 端口预设
func choiceports(portname string) []string {
	var ports []string
	if portname == "all" {
		for p := range Utils.Portmap {
			ports = append(ports, p)
		}
		return ports
	}

	if Utils.Namemap[portname] != nil {
		ports = append(ports, Utils.Namemap[portname]...)
		return ports
	} else if Utils.Typemap[portname] != nil {
		ports = append(ports, Utils.Typemap[portname]...)
		return ports
	} else {
		return []string{portname}
	}
}

func Printportconfig() {
	fmt.Println("当前已有端口配置: (根据端口类型分类)")
	for k, v := range Utils.Namemap {
		fmt.Println("	", k, ": ", strings.Join(v, ","))
	}
	fmt.Println("当前已有端口配置: (根据服务分类)")
	for k, v := range Utils.Typemap {
		fmt.Println("	", k, ": ", strings.Join(v, ","))
	}
}
