package core

import (
	"fmt"
	. "github.com/chainreactors/gogo/v2/pkg"
	"github.com/chainreactors/gogo/v2/pkg/fingers"
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
	fmt.Println("name\tindex\tip         \tport     \tmod\tping\tsmartPort\tsmartIp\tversion\texploit\toutputFile\toutputPath")
	for name, workflows := range LoadWorkFlow() {
		fmt.Println(name + ": ")
		for i, w := range workflows {
			fmt.Printf("\t%-d\t%-15s\t%-10s\t%-s\t%-t\t%-10s\t%-10s\t%-5d\t%-10s\t%-10s\t%-10s\t%-10s\n", i, w.IP, w.Ports, w.Mod, w.Ping, w.SmartProbe, w.IpProbe, w.Version, w.Exploit, w.File, w.Path, w.Description)
		}
	}
}

func PrintExtract() {
	fmt.Println("name\tregexp")
	for name, extract := range fingers.PresetExtracts {
		fmt.Printf("%s\t%q\n", name, extract.String())
	}
}

//func Usage() string {
//	return `
//Usage of gogo:
//
//   -k string   key,启动密码(必须输入)
//   -version     输出版本号
//   -debug bool  输出每个请求的日志, 用来debug.
//   -plugindebug bool 输出plugin模块中的报错堆栈
//
//   INPUT params:
//      -ip string  IP地址, 支持逗号分割的输入 like 192.168.1.1/24,172.16.1.1/24
//      -p string   ports, (default "top1")
//         default 非特殊指定其他端口, 均默认使用这种方式扫描, 使用socket发送GET包
//         nbt  使用netbios收集域,sharing,DC信息
//         oxid 使用wmi协议收集网卡信息
//         smb  使用ntlm协议收集主机名/域信息
//         wmi 使用wmi的ntlm协议收集信息,与smb的协议收集到的内容一致
//         snmp 使用snmp public收集信息
//         icmp/ping 使用ping判断存活
//         arp 使用arp协议判断ip存活, 并收集mac地址
//         winrm 不太常用,暂时删除
//
//      -m string  mod, 扫描模式：(每次只能选择一个生效)
//            default (默认值, 资产扫描),
//            s B段启发式扫描,
//            ss A段启发式扫描
//            sc 以ss模式发现所有存活C段(但不会进行端口扫描)
//      -l string  listfile, 从文件中读取任务,例如:-l ip.txt
//      -j string	 jsonfile, 从输出的json中读取任务,例如:-j 1.json
//      -L bool    Listfile_from_stdin , 从管道中读数据的时候,指定数据类型为行分割的数据
//      -J bool    Jsonfile_from_stdin 从管道中读数据的时候, 指定数据为前一次的扫描结果, 从传入管道前请base64, 否则可能因为EOF字符被截断
//      -F file    Format, 格式化扫描结果
//      -w string  workflow, 调用自动化配置的预设
//
//   SMART CONFIGS
//      -sp string  smart_probe,启发式扫描端口探针,-m s 下默认为80, -m ss下默认为icmp
//      -ipp string smart_ip_probe, -ss模式ip探针,默认1,254
//      -no bool	  noscan,   (依赖-m s/ss) 高级扫描模式只探测存活网段不进行端口扫描
//      -ping bool  pingscan, 在端口扫描前插入一次ping 喷洒, 存活的ip才会被加入端口扫描.
//
//   OUTPUT params:
//      -f string  file,  输出文件名,默认为空
//      -path string 指定输出的目录, -f参数默认为当前目录, -af/hf参数为程序绝对目录
//      -af bool	autofile,   自动生成文件名,格式为 ".IP_port_number.json"
//      -hf bool  hiddenfile,   自动生成隐藏文件名.
//
//      -o string  output,  输出到命令行的格式:clean,full(default) or json, 以及ip, url, target, zombie(仅限-F), cs(仅限-F) 等多种输出格式
//      -O string  FileOutput, 输出到文件的格式: clean, full, json(default) 以及ip, url, target
//      -C bool   Clear,   强制关闭输出文件压缩, 变成明文输出
//      -c string    在指定了-f的情况下强制打开命令行输出扫描结果
//      -q bool   quiet, 不在命令行输出进度日志
//
//      -P string Print, 查看配置预设  port|nuclei|workflow|extract
//         port 端口预设
//         nuclei 可以选用的poc
//         workflow workflow预设
//         extract  extract预设
//
//   CONFIGURATIONS params:
//      -d int     delay, 超时,默认2s (default 2)
//      -D int     Https_Delay,  https协议单独配置的超时, 默认4s
//      -s bool 	 spray,  喷洒模式扫描,ip生成器将端口为优先,端口数量大于100将自动启用
//      -ns bool	 no_spray,  强制关闭spray扫描
//      -t int     threads, (default 4000), windows下默认1000, fd限制为1024的linux下默认为900
//      -v bool    version_scan, 扫描详细指纹.默认为打开状态,存在-v参数则关闭.
//      -e bool    exploit_scan, 启用漏洞插件扫描,目前有ms17-010与shiro(默认key),以及nuclei的poc,将会自动选用
//      -E string  Exp_name, 强制指定poc的tag或name, 指定-E all 时为全部poc
//      -ef string exploit_file, 指定json文件为nucleipoc
//      -suffix string 指定特定的url
//      -payload 用来自定义替换nuclei poc中的参数, 需要nuclei poc预定义占位符
//      -extract 自定义需要提取的内存, 输入正则表达式, 支持一些常见的预设
//      -extracts 逗号分割的多个extractor预设
//`
//}
