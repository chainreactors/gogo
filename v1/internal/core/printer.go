package core

import (
	"fmt"
	. "getitle/v1/pkg"
	"strings"
)

func Printportconfig() {
	fmt.Println("当前已有端口配置: (根据端口类型分类)")
	for k, v := range *NameMap {
		fmt.Println("	", k, ": ", strings.Join(v, ","))
	}
	fmt.Println("当前已有端口配置: (根据服务分类)")
	for k, v := range *TagMap {
		fmt.Println("	", k, ": ", strings.Join(v, ","))
	}
}

func PrintNucleiPoc() {
	fmt.Println("Nuclei Pocs")
	for k, v := range TemplateMap {
		fmt.Println(k + ":")
		for _, t := range v {
			var payload string
			for _, request := range t.RequestsHTTP {
				for name, _ := range request.Payloads {
					payload += name + "\t"
				}
			}
			for _, request := range t.RequestsNetwork {
				for name, _ := range request.Payloads {
					payload += name + "\t"
				}
			}
			if payload != "" {
				payload = "payloads: " + payload
			}
			fmt.Printf("\t%s\t%s\t%s\t%s %s\n", t.Id, t.Info.Name, t.Info.Severity, t.Info.Description, payload)
		}
	}
}

func PrintWorkflow() {
	fmt.Println("name\tindex\tip         \tport     \tmod\tping\tarp\tsmartPort\tsmartIp\tversion\texploit\toutputFile\toutputPath")
	for name, workflows := range LoadWorkFlow() {
		fmt.Println(name + ": ")
		for i, w := range workflows {
			fmt.Printf("\t%-d\t%-15s\t%-10s\t%-s\t%-t\t%-t\t%-10s\t%-10s\t%-5d\t%-10s\t%-10s\t%-10s\t%-10s\n", i, w.IP, w.Ports, w.Mod, w.Ping, w.Arp, w.SmartProbe, w.IpProbe, w.Version, w.Exploit, w.File, w.Path, w.Description)
		}
	}
}

func PrintExtract() {
	fmt.Println("name\tregexp")
	for name, extract := range PresetExtracts {
		fmt.Printf("%s\t%q\n", name, extract.String())
	}
}
