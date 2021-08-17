package core

import (
	"fmt"
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
	} else if utils.Typemap[portname] != nil {
		ports = append(ports, utils.Typemap[portname]...)
		return ports
	} else {
		return []string{portname}
	}
}

func Printportconfig() {
	fmt.Println("当前已有端口配置: (根据端口类型分类)")
	for k, v := range utils.Namemap {
		fmt.Println("	", k, ": ", strings.Join(v, ","))
	}
	fmt.Println("当前已有端口配置: (根据服务分类)")
	for k, v := range utils.Typemap {
		fmt.Println("	", k, ": ", strings.Join(v, ","))
	}
}
