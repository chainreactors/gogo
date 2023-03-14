# gogo
高度可控可拓展的自动化的扫描引擎, 为红队[设计](https://chainreactors.github.io/wiki/gogo/design/).

## Features
* 自由的端口配置
* 支持主动/被动指纹识别
* 关键信息提取, 如title, cert 以及自定义提取信息的正则
* 支持nuclei poc
* 无害的扫描, 每个添加的poc都经过人工审核
* 可控的启发式扫描
* 超强的性能, 最快的速度, 尽可能小的内存与CPU占用.
* 最小发包原则, 尽可能少地发包获取最多的信息
* 支持DSL, 可以通过简单的配置自定义自己的gogo
* 完善的输出与输出设计
* 几乎不依赖第三方库, 纯原生go编写

## QuickStart
完整的文档与教程位于wiki: https://chainreactors.github.io/wiki/gogo/

最简使用, 指定网段进行默认扫描, 并在命令行输出

`gogo -i 192.168.1.1/24 -p win,db,top2 `

一些常用的端口配置:
* `-p -`  等于`-p 1-65535`
* `-p all` port.yaml中的所有端口
* `-p common` 内网常用端口
* `-p top2,top3` 外网常见web端口

当目标范围的子网掩码小于24时, 建议启用 smart模式扫描(原理见doc), 例如子网掩码为16时(输出结果较多, 建议开启--af输出到文件, 命令行只输出日志)

`gogo -i 172.16.1.1/16 -m s -p top2,win,db --af`

这个命令有些复杂, 但不用担心, 可以使用workflow代替.如 `gogo -w s -i 172.16.1.1/16`, --af的意思为自动生成文件, 使用-w时为自动开启.

当目标范围的子网掩码小于24, 建议启用supersmart模式扫描, 例如:

`gogo -i 10.0.0.0/8 -m ss -p top2,win,db --af`

常用的配置已经被集成到workflow中, 例如使用supersmart mod 扫描10段内网, `gogo -w 10`即可. 如果需要自定义网段, 则是`gogo -w 10 -i 11.0.0.0/8`, 通过-i参数覆盖-w 10 中的ip字段. 因为语义可能造成混淆, 也可以使用语义化的workflow `gogo -w ss -i 11.1.1.1/8`.

workflow中的预设参数优先级低于命令行输入, 因此可以通过命令行覆盖workflow中的参数. 

可以使用`-P workflow`查看所有的workflow预设, 更快捷的使用gogo.

如果指定了--af或者-w, 默认的输出结果为deflate算法压缩后的json文件, 可以使用-F格式化扫描结果

`gogo -F result.dat`

## 示例

**一个简单的任务**

`gogo -i 81.68.175.32/28 -p top2`

```
gogo -i 81.68.175.32/28 -p top2
[*] Current goroutines: 1000, Version Level: 0,Exploit Target: none, PortSpray: false ,2022-07-07 07:07.07
[*] Start task 81.68.175.32/28 ,total ports: 100 , mod: default ,2022-07-07 07:07.07
[*] ports: 80,81,82,83,84,85,86,87,88,89,90,443,1080,2000,2001,3000,3001,4443,4430,5000,5001,5601,6000,6001,6002,6003,7000,7001,7002,7003,9000,9001,9002,9003,8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,8000,8001,8002,8003,8004,8005,8006,8007,8008,8009,8010,8011,8012,8013,8014,8015,8016,8017,8018,8019,8020,6443,8443,9443,8787,7080,8070,7070,7443,9080,9081,9082,9083,5555,6666,7777,9999,6868,8888,8889,9090,9091,8091,8099,8763,8848,8161,8060,8899,800,801,888,10000,10001,10080 ,2022-07-07 07:07.07
[*] Scan task time is about 8 seconds ,2022-07-07 07:07.07
[+] http://81.68.175.33:80      nginx/1.16.0            nginx                   bd37 [200] HTTP/1.1 200
[+] http://81.68.175.32:80      nginx/1.18.0 (Ubuntu)           nginx                   8849 [200] Welcome to nginx!
[+] http://81.68.175.34:80      nginx           宝塔||nginx                     f0fa [200] 没有找到站点
[+] http://81.68.175.34:8888    nginx           nginx                   d41d [403] HTTP/1.1 403
[+] http://81.68.175.34:3001    nginx           webpack||nginx                  4a9b [200] shop_mall
[+] http://81.68.175.37:80      Microsoft-IIS/10.0              iis10                   c80f [200] HTTP/1.1 200             c0f6 [200] 安全入口校验失败
[*] Alive sum: 5, Target sum : 1594 ,2022-07-07 07:07.07
[*] Totally run: 4.0441884s ,2022-07-07 07:07.07
```

如果要联动其他工具, 可以指定`-q/--quiet`关闭日志信息, 只保留输出结果.

**输出到文件**

`gogo -i 81.68.175.32 --af`

可以看到在gogo二进制文件同目录下, 生成了`.81.68.175.32_28_all_default_json.dat1`, 该文件是deflate压缩的json文件.

通过gogo格式化该文件, 获得human-like的结果

```
 gogo  -F .\.81.68.175.32_28_all_default_json.dat1
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
...
...
```

一些常用的输出格式.

* `-o jl` , 一行一个json, 可以通过管道传给jq实时处理
* `-o color` , 带颜色的输出

并且可以通过--filter过滤出想要的结果

过滤指定字段的值`-F 1.json --filter framework::redis -o ip`

`::` 为模糊匹配, `==` 为精准匹配, `!=` 为不等于, `!:` 为不包含

`-F 1.json -f file` 重新输出到文件, `--af` 输出到文件根据config自动生成文件名

关于输入输出以及各种高级用法请见[gogo的wiki](https://chainreactors.github.io/wiki/gogo/start/#output)

## 注意事项

* **(重要)**因为并发过高,可能对路由交换设备造成伤害, 例如某些家用路由设备面对高并发可能会死机, 重启, 过热等后果. 因此在外网扫描的场景下**建议在阿里云,华为云等vps上使用**,如果扫描国外资产,建议在国外vps上使用.本地使用如果网络设备性能不佳会带来大量丢包. 如果在内网扫描需要根据实际情况调整并发数.
* 如果使用中发现疯狂报错,大概率是io问题(例如多次扫描后io没有被正确释放,或者配合proxifier以及类似代理工具使用报错),可以通过重启电脑,或者虚拟机中使用,关闭代理工具解决.如果依旧无法解决请联系我们.
* 还需要注意,upx压缩后的版本虽然体积小,但是有可能被杀软杀,也有可能在部分机器上无法运行.
* 一般情况下无法在代理环境中使用,除非使用-t参数指定较低的速率(默认并发为4000).
* gogo本身并不具备任何攻击性, 也无法对任何漏洞进行利用.
* **使用gogo需先确保获得了授权, gogo反对一切非法的黑客行为**

### 使用场景并发推荐

默认的并发linux为4000, windows为1000, 为企业级网络环境下可用的并发. 不然弱网络环境(家庭, 基站等)可能会导致网络dos

建议根据不同环境,手动使用-t参数指定并发数.

* 家用路由器(例如钓鱼, 物理, 本机扫描)时, 建议并发 100-500
* linux 生产网网络环境(例如外网突破web获取的点), 默认并发4000, 不需要手动修改
* windows 生产网网络环境, 默认并发1000, 不需要手动修改
* 高并发下udp协议漏报较多, 例如获取netbois信息时, 建议单独对udp协议以较低并发重新探测
* web的正向代理(例如regeorg),建议并发 10-30
* 反向代理(例如frp), 建议并发10-100

如果如果发生大量漏报的情况, 大概率是网络环境发生的阻塞, 倒是网络延迟上升超过上限.

因此也可以通过指定 `-d 5 `(tcp默认为2s, tls默认为两倍tcp超时时间,即4s)来提高超时时间, 减少漏报.

未来也许会实现auto-tune, 自动调整并发速率

**这些用法大概只覆盖了一小半的使用场景, 请[阅读文档](https://chainreactors.github.io/wiki/gogo/)**

## Make

### 手动编译

```bash
# download
git clone --recurse-submodules https://github.com/chainreactors/gogo
cd gogo/v2

# sync dependency
go mod tidy   

# generate template.go
go generate

# build 
go build .
```

如果需要编译windows xp/2003的版本, 请先使用高版本的go生成templates. 再使用go 1.11编译即可.

## Similar or related works

* [ServerScan](https://github.com/Adminisme/ServerScan) 早期的简易扫描器, 功能简单但开拓了思路
* [fscan](https://github.com/shadow1ng/fscan) 简单粗暴的扫描器, 细节上有不少问题, 胜在简单. 参考其简单无脑的命令行, 设计了workflow相关功能.
* [kscan](https://github.com/lcvvvv/kscan) 功能全面的扫描器, 从中选取合并了部分指纹
* [ladongo](https://github.com/k8gege/LadonGo) 集成了各种常用功能, 从中学习了多个特殊端口的信息收集
* [cube](https://github.com/JKme/cube) 与fscan类似, 从中学习了NTLM相关协议的信息收集

gogo从这些相似的工作中改进自身. 感谢前人的工作. 

细节上的对比请看[文档](https://chainreactors.github.io/wiki/gogo/design/)

## THANKS
* https://github.com/projectdiscovery/nuclei-templates
* https://github.com/projectdiscovery/nuclei
* https://github.com/JKme/cube
