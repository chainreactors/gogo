# gogo
专注内网自动化的扫描引擎

README Version 2.5.0

## Usage

```
Usage of ./gogo:

   -k string   key,启动密码(必须输入) 
   -debug bool  输出每个请求的错误日志, 用来debug. 可以附加-proxy url, 使用代理调试指纹或poc(单独-proxy无法使用)
   
   INPUT params:
      -ip string   IP地址, 支持逗号分割的输入 like 192.168.1.1/24,172.16.1.1/24
      -eip string exclude_ip, 排除指定的ip地址,支持cidr, 支持逗号分割 -eip 192.168.1.1/28,192.168.1.199 
      -p string   ports, (default "top1")
         default 非特殊指定其他端口, 均默认使用这种方式扫描, 使用socket发送GET包
         nbt  使用netbios收集域,sharing,DC信息
         oxid 使用wmi协议收集网卡信息
         smb  使用ntlm协议收集主机名/域信息
         wmi 使用wmi的ntlm协议收集信息,与smb的协议收集到的内容一致 
         snmp 使用snmp public收集信息
         icmp/ping 使用ping判断存活
         arp 使用arp协议判断ip存活, 并收集mac地址
         winrm 不太常用,暂时删除

      -m string  mod, 扫描模式：(每次只能选择一个生效)
            default (默认值, 资产扫描),
            s B段启发式扫描,
            ss A段启发式扫描
            sc 以ss模式发现所有存活C段(但不会进行端口扫描)
            a 根据默认配置自动启发式扫描
      -l string  listfile, 从文件中读取任务,例如:-l ip.txt
      -j string	 jsonfile, 从输出的json中读取任务,例如:-j 1.json
      -L bool    List_File_From_Pipe , 从管道中读数据的时候,指定数据类型为行分割的数据
      -J bool    Json_File_From_Pipe 从管道中读数据的时候, 指定数据为前一次的扫描结果, 从传入管道前请base64, 否则可能因为EOF字符被截断
      -F file    Format, 格式化扫描结果
      -w string  workflow, 调用自动化配置的预设  
      
   SMART CONFIGS
      -sp string  smart_probe,启发式扫描端口探针,-m s 下默认为80, -m ss下默认为icmp
      -ipp string smart_ip_probe, -ss模式ip探针,默认1
      -no bool	  noscan,   (依赖-m s/ss) 高级扫描模式只探测存活网段不进行端口扫描
      -ping bool  pingscan, 在端口扫描前插入一次ping 喷洒, 存活的ip才会被加入端口扫描.
 
   OUTPUT params:
      -o string  output,  输出到命令行的格式:clean,full(default) or json, 以及ip, url, target, zombie(仅限-F), cs(仅限-F) 等多种输出格式
      -O string  FileOutput, 输出到文件的格式: clean, full, json(default) 以及ip, url, target
      -f string  file,  输出文件名,默认为空
      -path string 指定输出的目录, -f参数默认为当前目录, -af/hf参数为程序绝对目录
      -af bool	autofile,   自动生成文件名,格式为 ".IP_port_number.json"
      -hf bool  hiddenfile,   自动生成隐藏文件名.
      -C bool   Clear,   强制关闭输出文件压缩, 变成明文输出

      -c string    在指定了-f的情况下强制打开命令行输出扫描结果
      -q bool   quiet, 不在命令行输出进度日志
      -P string Print, 查看配置预设  port|nuclei|workflow|extract 
         port 端口预设
         nuclei 可以选用的poc
         workflow workflow预设
         extract  extract预设

   CONFIGURATIONS params:
      -version     输出版本号
      -d int     delay, 超时,默认2s (default 2)
      -D int     Https_Delay,  https协议单独配置的超时, 默认4s
      -s bool 	 spray,  喷洒模式扫描,ip生成器将端口为优先,端口数量大于100将自动启用
      -ns bool	 no_spray,  强制关闭spray扫描
      -t int     threads, (default 4000), windows下默认1000, fd限制为1024的linux下默认为900
      -v bool    version_scan, 扫描详细指纹.默认为打开状态,存在-v参数则关闭.
      -e bool    exploit_scan, 启用漏洞插件扫描,目前有ms17-010与shiro(默认key),以及nuclei的poc,将会自动选用
      -E string  Exp_name, 强制指定poc的tag或name, 指定-E all 时为全部poc
      -ef string exploit_file, 指定json文件为nucleipoc
      -up string upload_file,  指定文件上传到云服务器
      -np bool   no_upload, 关闭自动上传扫描结果到云服务器
      -suffix string 指定特定的url
      -payload 用来自定义替换nuclei poc中的参数, 需要nuclei poc预定义占位符
      -extract 自定义需要提取的内存, 输入正则表达式, 支持一些常见的预设
      -extracts 逗号分割的多个extractor预设
```

## DOWNLOAD
### 版本号命名规则
example: 1.1.1.1

第一位数字代表互不兼容的命令行UI或输出结果;

第二位数字代表代码结构或者功能上的更新;

第三位数字代表bug的修复或者小功能更新;

第四位数字不一定每个版本都有, 代表指纹或poc的更新.


### release
完全版本打包下载: https://github.com/chainreactors/gogo/releases/latest

理论上支持全操作系统, 需要编译某些稍微罕见的特殊版本可以联系我帮忙编译.

单文件下载链接:

**windows**

[windows32upx](https://sangfor-release.oss-cn-shanghai.aliyuncs.com/fscan/windows_386_upxs.exe)
[windows32](https://sangfor-release.oss-cn-shanghai.aliyuncs.com/fscan/windows_386s.exe)
[windows64](https://sangfor-release.oss-cn-shanghai.aliyuncs.com/fscan/windows_amd64s.exe)
[windows64upx](https://sangfor-release.oss-cn-shanghai.aliyuncs.com/fscan/windows_amd64_upxs.exe)

**linux**

[linux_amd64](https://sangfor-release.oss-cn-shanghai.aliyuncs.com/fscan/linux_amd64)
[linux_amd32](https://sangfor-release.oss-cn-shanghai.aliyuncs.com/fscan/linux_386)
[linux_arm64](https://sangfor-release.oss-cn-shanghai.aliyuncs.com/fscan/linux_arm64)
[linux_mips64](https://sangfor-release.oss-cn-shanghai.aliyuncs.com/fscan/linux_mips64)

**mac**

[mac](https://sangfor-release.oss-cn-shanghai.aliyuncs.com/fscan/darwin_amd64)

## QuickStart
最简使用, 建议只在c段及以下场景使用, 大于b段则建议使用启发式扫描.

`gogo -k [key] -ip 192.168.1.1/24 -p win,db,top2 `

启发式扫描

`gogo -k [key] -ip 172.16.1.1/16 -m s -p all -e -v -af`

扫描结果格式化

`gogo -k [key] -F result.dat`


### workflow
查看全部可用工作流

`gogo -k [key] -P workflow`

使用工作流, 自动配置启发式扫描, 启发式扫描10段常见端口

`gogo -k [key] -w 10`

workflow 使用思维导图

![](doc/img/pipeline.png)

## 参数详解

所有用法都需输入-k [密钥]

### target输入
允许多种类似的输入, 有不同的效果, 在不同的环境下使用

1. 直接输入cidr,参数-ip 1.1.1.1/24, 支持逗号分割
2. 从文件中读ip列表, 参数 -l 1.txt
3. 从结果中读任务列表,参数 -j 1.json
4. 从管道中读取列表, -L
5. 从管道中读取结果, -J

### 端口配置

gt支持非常灵活的端口配置

参看端口预设,参数 -P port

使用端口预设灵活配置端口: `-p top2,http,1-1000,65534`

### 输出

输出分为两大类,输出到文件或输出到命令行. 在webshell场景下,通常无法输出到命令行, 因此需要输出到文件.

gt对两种场景分别设计了不同的输出逻辑.

#### 输出到命令行

默认即可输出到命令行,但是在选择输出到文件的时候会关闭命令行输出.此时可以使用-c手动开启

输出格式:clean,full(default) or json, 以及ip, url, target 等单独或多个字段的组合

命令行full格式输出结果如下:
```
gogo -k yunzi -ip 81.68.175.32/28 -p top2
[*] Current goroutines: 1000, Version Level: 0,Exploit Target: none, PortSpray Scan: false ,2022-07-07 07:07.07
[*] Starting task 81.68.175.32/28 ,total ports: 100 , mod: default ,2022-07-07 07:07.07
[*] ports: 80,81,82,83,84,85,86,87,88,89,90,443,1080,2000,2001,3000,3001,4443,4430,5000,5001,5601,6000,6001,6002,6003,7000,7001,7002,7003,9000,9001,9002,9003,8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,8000,8001,8002,8003,8004,8005,8006,8007,8008,8009,8010,8011,8012,8013,8014,8015,8016,8017,8018,8019,8020,6443,8443,9443,8787,7080,8070,7070,7443,9080,9081,9082,9083,5555,6666,7777,9999,6868,8888,8889,9090,9091,8091,8099,8763,8848,8161,8060,8899,800,801,888,10000,10001,10080 ,2022-07-07 07:07.07
[*] Scan task time is about 8 seconds ,2022-07-07 07:07.07
[+] http://81.68.175.33:80      nginx/1.16.0            nginx                   bd37 [200] HTTP/1.1 200
[+] http://81.68.175.32:80      nginx/1.18.0 (Ubuntu)           nginx                   8849 [200] Welcome to nginx!
[+] http://81.68.175.34:80      nginx           宝塔||nginx                     f0fa [200] 没有找到站点
[+] http://81.68.175.34:8888    nginx           nginx                   d41d [403] HTTP/1.1 403
[+] http://81.68.175.34:3001    nginx           webpack||nginx                  4a9b [200] shop_mall
[+] http://81.68.175.37:80      Microsoft-IIS/10.0              iis10                   c80f [200] HTTP/1.1 200
[+] http://81.68.175.36:80      nginx   PHP     nginx                   babe [200] 风闻客栈24小时发卡中心 - 风闻客栈24小时发卡中心
[+] http://81.68.175.38:80                      webpack                 c581 [200] Vue App
[+] http://81.68.175.45:80      Apache          宝塔                    f0fa [200] 没有找到站点
[+] http://81.68.175.43:80      nginx/1.9.9             nginx                   7cd7 [200] 首页 - 世界名画欣赏
[+] http://81.68.175.45:888     Apache                                  ae22 [403] 403 Forbidden
[+] http://81.68.175.45:8888    nginx           宝塔面板||nginx                 c0f6 [200] 安全入口校验失败
[*] Alive sum: 12, Target sum : 1594 ,2022-07-07 07:07.07
[*] Totally run: 4.0441884s ,2022-07-07 07:07.07
```

-q 参数关闭进度输出, 只保留-o指定的输出结果

#### 输出到文件

通过`-f filename` 或 `-af` 或 `-hf` 指定输出的文件名, 则由命令行输出自动转为文件输出, 会关闭命令行的结果输出, 只保留进度输出(进度输出会同步到`.sock.lock`文件中). 适用于webshell场景等无交互式shell的场景.

注1. 如果输出到文件, 文件默认路径与gt二进制文件同目录. 需要修改目录, 请指定`-path [path]`

输出到文件的结果, 需要使用`-F filename`格式化. 效果如下:

```
 gogo -k [key] -F .\.81.68.175.32_28_all_default_json.dat1
Scan Target: 81.68.175.32/28, Ports: all, Mod: default
Exploit: none, Version level: 0

[+] 81.68.175.32
        http://81.68.175.32:80  nginx/1.18.0 (Ubuntu)           nginx                   8849 [200] Welcome to nginx!
        tcp://81.68.175.32:22                   *ssh                     [tcp]
        tcp://81.68.175.32:389                                           [tcp]
[+] 81.68.175.33
        tcp://81.68.175.33:3306                 *mysql                   [tcp]
        tcp://81.68.175.33:22                   *ssh                     [tcp]
        http://81.68.175.33:80  nginx/1.16.0            nginx                   bd37 [200] HTTP/1.1 200
[+] 81.68.175.34
        tcp://81.68.175.34:3306                 mysql 5.6.50-log                         [tcp]
        tcp://81.68.175.34:21                   ftp                      [tcp]
        tcp://81.68.175.34:22                   *ssh                     [tcp]
        http://81.68.175.34:80  nginx           宝塔||nginx                     f0fa [200] 没有找到站点
        http://81.68.175.34:8888        nginx           nginx                   d41d [403] HTTP/1.1 403
        http://81.68.175.34:3001        nginx           webpack||nginx                  4a9b [200] shop_mall
[+] 81.68.175.35
        http://81.68.175.35:47001       Microsoft-HTTPAPI/2.0           microsoft-httpapi                       e702 [404] Not Found
[+] 81.68.175.36
        http://81.68.175.36:80  nginx   PHP     nginx                   babe [200] 风闻客栈24小时发卡中心 - 风闻客栈24小时发卡中心
        tcp://81.68.175.36:22                   *ssh                     [tcp]
[+] 81.68.175.37
        http://81.68.175.37:80  Microsoft-IIS/10.0              iis10                   c80f [200] HTTP/1.1 200
[+] 81.68.175.38
        tcp://81.68.175.38:22                   *ssh                     [tcp]
        http://81.68.175.38:80                  webpack                 c581 [200] Vue App
[+] 81.68.175.39
        tcp://81.68.175.39:3389                 *rdp                     [tcp]
[+] 81.68.175.40
        http://81.68.175.40:47001       Microsoft-HTTPAPI/2.0           microsoft-httpapi                       e702 [404] Not Found
        http://81.68.175.40:5985        Microsoft-HTTPAPI/2.0           microsoft-httpapi                       e702 [404] Not Found
        tcp://81.68.175.40:3389                 *rdp                     [tcp]
[+] 81.68.175.41
        tcp://81.68.175.41:3389                 *rdp                     [tcp]
[+] 81.68.175.42
        http://81.68.175.42:47001       Microsoft-HTTPAPI/2.0           microsoft-httpapi                       e702 [404] Not Found
        http://81.68.175.42:5985        Microsoft-HTTPAPI/2.0           microsoft-httpapi                       e702 [404] Not Found
        tcp://81.68.175.42:3389                 *rdp                     [tcp]
[+] 81.68.175.43
        http://81.68.175.43:80  nginx/1.9.9             nginx                   7cd7 [200] 首页 - 世界名画欣赏
        tcp://81.68.175.43:22                   *ssh                     [tcp]
[+] 81.68.175.44
        http://81.68.175.44:47001       Microsoft-HTTPAPI/2.0           microsoft-httpapi                       e702 [404] Not Found
        tcp://81.68.175.44:3389                 *rdp                     [tcp]
[+] 81.68.175.45
        tcp://81.68.175.45:22                   *ssh                     [tcp]
        http://81.68.175.45:80  Apache          宝塔                    f0fa [200] 没有找到站点
        http://81.68.175.45:888 Apache                                  ae22 [403] 403 Forbidden
        tcp://81.68.175.45:21                   ftp                      [tcp]
        http://81.68.175.45:8888        nginx           宝塔面板||nginx                 c0f6 [200] 安全入口校验失败
...
...
```

可以使用`-F 1.json -o c`来着色

可以使用`-F 1.json -o ip` 来过滤出指定字段

过滤指定字段的值`-F 1.json -filter framework::redis -o ip`

`::` 为模糊匹配, `==` 为精准匹配.

`-f file` 重新输出到文件, `-af` 输出到文件根据config自动生成文件名

### ~~启发式扫描配置~~ (保留文档, 已被workflow取代)
如果在使用-w workflow的情况下, 继续添加-sp, -ipp, 可以覆盖workflow中的预设值, 提高workflow的灵活性

-m s 为喷洒C段模式,子网掩码要小于24才能使用

-m ss 为喷洒B段模式, 子网掩码要小于16才能使用

-m sc 为在A段中收集存活C段, 子网掩码要小于16才能使用

-no 只进行启发式扫描,在喷洒到网段后不进行全扫描. 可以配合-f参数将启发式扫描喷洒到的网段输出到文件.例如 `-s -no -f aliveC.txt`

-sp (smart probe)控制启发式扫描的探针,默认为icmp协议,可以手动指定为其他配置,例如`-sp 80,icmp,445 ` 来在禁ping的环境下使用

-ipp (IP probe) 控制-ss模式中的B段喷洒的ip探针,-ss模式默认只扫描每个C段的第一个ip,例如192.168.1.1. 可以手动修改,指定`-ipp 1,254,253`

## 拓展功能

**标准使用场景**

指定网段, 指定目标端口

`./gt.exe -ip 172.16.1.1/24 -p top2,db,mail,jboss,1000-1009,12345,54321`

**端口Spray模式**

任务生成器会以端口优先生成任务, 而非默认的ip优先.

`./gt.exe -ip 172.16.1.1/24 -p top2 -s`

**主动指纹识别**

当前包括数千条web指纹, 数百条favicon指纹以及数十条tcp指纹

默认情况下只收集不主动发包的指纹. 如需进行主动的指纹识别, 需要添加-v参数.

`./gt.exe -ip 192.168.1.1/24 -p top2 -v `

**主动漏洞探测**

gogo并非漏扫工具,因此不会支持sql注入,xss之类的通用漏洞探测功能.

为了支持内网更好的自动化, 集成了nuclei的poc, 可以用来编写poc批量执行某些特定的扫描任务, 一级一些默认口令登录的poc

因为nuclei的中poc往往攻击性比较强, 因此需要手动修改适应红队环境

目前已集成的pocs见v1/config/nuclei, 以及ms17010, shiro, snmp等特殊的漏洞

为了更好的探测漏洞, 建议同时开启-v 主动指纹识别

使用:

`./gt.exe -ip 192.168.1.1/24 -p top2 -v -e`

**高级启发式扫描** 

[见gogo设计文档3-启发式扫描](doc/gogo设计文档3-启发式扫描.md)


**特殊端口支持**

部分特殊端口以插件的形式支持, 而非默认的探测端口状态. 可以收集一些额外的信息.

WMI
`./gt.exe -ip 172.16.1.1/24 -p wmi`

OXID:

`./gt.exe -ip 172.16.1.1/24 -p oxid`

NBTScan

`./gt.exe -ip 172.16.1.1/24 -p nbt`

PING

`./gt.exe -ip 172.16.1.1/24 -p icmp`

snmp

`./gt.exe -ip 172.16.1.1/24 -p snmp`

SMB
`./gt.exe -ip 172.16.1.1/24 -p smb`

可以任意组合使用,例如:
`./gt.exe -ip 172.16.1.1/24 -p smb,wmi,oxid,nbt,icmp,80,443,top2`

## 注意事项

* **(重要)**因为并发过高,性能限制主要来自路由器设备.因此**建议在阿里云,华为云等vps上使用**,如果扫描国外资产,建议在国外vps上使用.本地使用如果网络设备性能不佳会带来大量丢包.

* 如果使用中发现疯狂报错,大概率是io问题(例如多次扫描后io没有被正确释放,或者配合proxifier以及类似代理工具使用报错),可以通过重启电脑,或者虚拟机中使用,关闭代理工具解决.如果依旧无法解决请联系我们.

* 还需要注意,upx压缩后的版本虽然体积小,但是有可能被杀软杀,也有可能在部分机器上无法运行.

* 一般情况下无法在代理环境中使用,除非使用-t参数指定较低的速率(默认协程池为4000).

### 使用场景并发推荐

默认的并发linux为4000, windows为1000, 为企业级网络环境下可用的并发. 不然弱网络环境(家庭, 基站等)可能会导致网络dos

建议根据不同环境,手动使用-t参数指定并发数. 

* 家用路由器(例如钓鱼, 物理, 本机扫描)时, 建议并发 100-500
* linux 生产网网络环境(例如外网突破web获取的点), 默认并发4000, 不需要手动修改 
* windows 生产网网络环境, 默认并发1000, 不需要手动修改
* 高并发下udp协议漏报较多, 例如获取netbois信息时, 建议单独对udp重新探测
* web的正向代理(例如regeorg),建议并发 10-50
* 反向代理(例如frp), 建议并发10-100

如果如果发生大量漏报的情况, 大概率是网络环境发生的阻塞, 倒是网络延迟上升超过上限.

因此也可以通过`-d 5 `(tcp默认为2s, tls为两倍tcp超时时间4s)来提高超时时间, 减少漏报.


**这些用法大概只覆盖了一半的使用场景, 更多的细节请阅读/doc目录下的设计文档**
## Make

### 手动编译
下载项目

`git clone --recurse-submodules https://github.com/chainreactors/gogo`

生成 template.go

`go generate`

编译

`go build .`

### build.bat:
需要依赖gox

`go get github.com/mitchellh/gox`

可以带两个参数, 第一个为版本号, 第二个为key, 不加则自动为空

`build.bat [key]`


### obfuscate.bat
发布前一些简单的混淆, 有更高明的手段可以忽略这部分

使用go-strip 混淆函数名, 使用upx加壳, 使用limelighter伪造证书. 需要将这三个工具添加到环境变量.

### release.bat 
自动将单个文件上传到alioss, 将README.md 二进制文件和一些小工具打包.

### full

`./build.bat [key] ; ./obfuscate.bat ; release.bat `

## THANKS

* https://github.com/k8gege/LadonGo
* https://github.com/projectdiscovery/nuclei-templates
* https://github.com/projectdiscovery/nuclei
* https://github.com/JKme/cube