## Change Note
* 2.0.2
  * 优化hash判断
  * 添加vcenter相关poc和信息收集
  * 优化函数,文件与包命名
* 2.0.1
  * workflow配置文件中支持字段iplist
  * 优化-P nuclei的输出, 现在可以看到可被payload参数覆盖的变量了
  * 整理代码结构, 文件命名, 包命名
* 2.0.0
  * 新增-w 参数, 用来选用workflow, 支持文件或逗号分割workflow名字或base64编码的json格式输入.
    例如:
    * `gt -w inter` 调用扫描三个内网地址的常见端口
    * `gt -w myworkflow.json`  使用自己编写的myworkflow.json文件
    * `gt -w [base64string]` 远程使用时不太方便传文件, 可以传入base64编码的myworkflow.json, 来无文件使用自定义workflow
  * 删除-m a参数, -m a 容易造成混淆, 已通过workflow功能代替
  * 新增-P workflow , 用来查看当前预设的workflow
  * 新增-P extract , 用来查询当前预设的extract
* 1.3.0
  * 新增arp扫描, 可使用-p arp 指定. windows下无法使用arp扫描
  * 新增-arp参数, 可以使用-arp喷洒存活ip, 类似-ping参数, 并且可以与-ping参数同时使用.效果叠加,自动去重.
  * 新增-iface指定arp扫描时使用的网卡, 默认为eth0
  * 重构runner与log代码
  * 优化404扫描逻辑
  * 优化extract输出
  * 新增-path参数, 用来指定输出文件目录, -f参数默认输出目录为当前目录, -af/hf参数默认输出目录为程序绝对目录. 可使用-path修改
* 1.2.2
  * 新增-extract参数, 指定正则表达式, 提取对应内容
  * 新增-extracts参数, 指定逗号分割的多个预设extract, 当前支持ip, idcard, url, header, body, response, cookie等
  * -ef支持base64编码的getitlepoc, 简单的poc不再需要上传文件
  * 优化了extract的命令行显示
  * -F参数现在支持对extract文件的解密了
  * extract文件的加密与其他文件相同, 默认使用加密, 可以使用-C参数强制不加密
* 1.2.1
  * **修复1.1.4之后引入的bug, close的端口也会加入到指纹识别中, 浪费了大量时间**
  * 新增404页面指纹识别, 有一套独特的逻辑, 能提升原有的指纹识别率, 合并在原有的-v参数中
  * 删除大量低质量的fofa 指纹
  * 略微优化getitle性能
  * 新增info输出块, 用来区分vuln
  * template 支持绑定多个fingerid
* 1.2.0
  * 支持了nuclei中有关extractor的功能, 可以自定义提取数据. 如果没有指定-f 将会在命令行输出预览, 如果指定了任意文件, 会创建 filename_extractor文件, 包含完整内容.
    命令行输出示例:
    `[+] http://222.186.57.62:85		Servlet/2.5 JSP/2.1			79f3 [200] \xb4\xf3\xc7\xf1ׯ\xb8\xd6\xcc\xfa\xcd\xf8\xcc\xfa\xb8\xe7\xc3\xc7\xd6\xfa\xca\xd6 [ Vuln: CVE-2022-21371 ] [ Vuln: weblogic-iiop-detect ] [ Vuln: weblogic-t3-detect ]  [ Extract: web-xml:<?xml version="1.0" encoding=" ... 33952bytes ] `
    文件输出则为完整内容
  * 支持通过参数配置nuclei poc中的payload, 例如`gt -ip 127.0.0.1 -p 8080 -v -e -payload auth:123456 -payload auth:dG9tY2F0OnMzY3JldA==`  , 可以将payload的auth参数替换为手动指定的, 支持多个参数, 每个参数的分割符号为 `:`
  * 新增-suffix参数, 用来常规扫描中指定url, 替换原来的`/` 目录
  * -j 参数支持 ip:port的多行输入
  * cve-2022-21371 weblogic 读文件
  * cve-2021-36260 海康摄像头 RCE
  * 删除部分容易产生误报的fofa 指纹
* 1.1.6
  * 使用1.11编译, 兼容windows server 2003/XP系统
  * 修复-no参数下扫描结果换行符丢失的bug
  * log文件无法创建的时候,会提供warn命令行信息, 但不会结束程序; -f/af/hf指定的文件无法创建的时候会提示错误原因并退出程序
* 1.1.4-1.1.5
  * 添加设计文档, 在doc目录下
  * 添加weblogic常见漏洞poc
  * 集成全部fofa指纹, 后续根据情况删改
  * 手动添加十数个指纹
  * 添加-debug参数, 用来判断网络状态
  * 优化代码逻辑, 删除无用代码
* 1.1.0 - 1.1.3
  * -F 命令添加 -filter子参数, 可以过滤想要的数据, 用法与gtfilter一致, -filter 可指定多个, 例如 -filter 1 filter 2
  * 新增-ping参数, 可以在默认扫描前插入一次ping喷洒, 如果存在-af, 存活ip将会单独输出
  * 新增-eip参数, 可以指定逗号分割的cidr或ip, 生成器将会跳过这些ip
  * 新增-version, 用来判断gt是否正常工作
  * 添加weblogic参见poc
  * -F 命令 添加-o json参数, 可以输出过滤后的json
  * 优化编译脚本
  * 重构file, generator模块
  * 重写了README.md, 在doc目录中添加了设计文档
* 1.0.10
  * 修复与优化了一些指纹以及输出. 修复多个输出的bug
  * 重写了README.md
  * 开始编写实现细节与设计思路的文档, 方便理解getitle是如何运作的来更好的使用getitile, 设计文档在doc目录下
* 1.0.9

  add:  
  * 大量优化代码结构
  * 重构输出，新增：
  * 现在可以使用-q参数完全关闭命令行日志输出(.sock.lock的输出不会关闭)
  * 现在-o参数可以接受title, url, target, ip, vulns, frameworks等输入,以及逗号分割的以上值自定义输出
  * 提高输出文件压缩率500%以上
  * 提高输出文件写入速度与压缩速度
  * 当-p参数指定的端口小于3, -m ss模式中,梯度下降扫描将跳过-s阶段
  * 增加了在linux系统中fd限制的警告.
  * 调整icmp超时时间, 在不影响扫描结果的清空下,提高了20%的速度
  * 更新数十个各类指纹
  * release中的二进制exe文件都加上了伪造的签名
  * 优化title的表现力

  fix:
  * 消除了一个潜在的条件竞争bug
  * 修复resp有可能导致的内存泄露问题
* 1.0.5-1.0,8
  
  add:
  * 重构了输出功能,现在所有输出都会使用defalte算法压缩,防止友商偷扫描报告
  * 实装DOUBLEPULSAR后门探测
  * -l 参数支持启发式扫描,进行批量启发式探测
  * 新增-o cs 输出到cobaltstrike的targets, -o zombie 输出到zombie密码爆破工具的输入
  * 支持管道输入,需要使用-L参数或者-J参数监听管道数据
  * 优化了windows信息收集,现在会映射build号到release版本
  * -ip 参数现在支持逗号分割
  * -F 参数现在支持-af 根据扫描内容格式化文件名
  * 更新大量常见指纹
  * 适配最新版gtfilter.py
  
  fix:
  * 修复指纹重复扫描的bug
  * 修复ip初始化的bug
  * 修复smb模块某些情况下报错的bug
* 1.0.3-1.0.4
  * smb协议指纹适配gtfilter
  * 重写smb协议扫描模块,更加稳定
  * 优化时间预测模块
  * 在子网掩码为32时,将自动关闭喷洒的输出
  * 在指定list中的ip为单个时,自动关闭cidr的输出
  * 支持逗号分割的-ip 参数输入值
* 1.0.2
  * 修改-j 参数默认线程为50
  * 修复-j upload 显示错误的bug
  * 启发式扫描的cidr现在可以正确的排序了
  * 优化代码结构
  * gtfilter适配最新版gt
  * 新增-hf参数,会自动隐藏文件名,并修改文件时间
  * 压缩加密ms17010的字节码,防止被杀软静态查杀
  * 添加-ef参数,可以从文件中读取nuclei poc,格式必须为poc,可以使用脚本将yaml转为poc使用
* 1.0.1
  * 修复-j参数无法使用的bug
  * 优化http逻辑,删除自动添加的referer头,隐藏user-agent
  * 优化-v参数逻辑,修复http主动扫描指纹在所有verison-level下都会生效的bug.现在-v参数会强制扫描所有指纹,以及favicon.
* 1.0.0
  * 使用nuclei的poc系统,目前已经实装tcp与http协议的poc,部分参数被删除,详情见readme.
  * 新增-e参数,现在会自动启用nuclei中的poc
  * 新增-E参数,可以手动指定漏洞的tag或name进行探测
  * 实装keep-alive,将会自动复用tcp连接
  * 新增-m sc模式,喷洒A段中的所有C段,-f保存到文件
  * 新增-af 参数,自动输出文件名并隐藏以及上传到云服务器
  * 当指定的端口数量大于100时,自动启用端口喷洒
  * 新增-ns 参数,关闭自动启用的端口喷洒
  * -F 参数现在可以使用-f输出到文件名,而不是管道,避免乱码问题
  * 修复.lock.sock导致的gt无法同时打开多个进程的bug
  * 优化输出界面,现在喷洒B,C段也会加到alive计数
  * 估算启发式扫描中每个C段或者端口中发现的资产数量
  * 新增端口猜测,在不启用-v参数的时候,自动根据端口号猜测服务,*号标记的服务为猜测所得
  * 重构gtfilter.py ,详情见gtfilter -h 或readme中. 新增了多个输出方式
  * 添加rdp,oracle,mssql等需要主动发包的tcp指纹
  * 新增wmi,smb,winrm(暂时禁用)的ntlm信息收集,可以收集到版本号,主机名,dns主机名等信息
  * -m a 将会探测多个预配置的内网网段,建议使用-no参数配合,查看配置可以使用-P inter.
  * 新增-P参数,输出一些配置信息,
    * -P help 输出可选配置
    * -P nuclei 输出nuclei tag与poc列表
    * -P port 输出端口配置
    * -P inter 内网配置
  * 新增hash字段,用来判断是否时同一个系统
  * 修复大量bug,提高稳定性,速度,性能.
* 0.3.12
  - 更新readme与更新日志稳定
  - 优化代码结构,提升代码运行效率
  - 优化gox.bat 编译脚本
* 0.3.11
  * 新增从json中读取扫描目标,如果忘了加-v或-e参数不再需要重新扫描,同时为之后漏扫作准备
  * 添加默认扫描中每个B段输出一次log
  * 自动修复未完成任务的json格式,不再需要手动修复
* 0.3.10
  * 使用go-strip清除编译信息
  * 修复一个启发式扫描子网掩码计算的bug
  * 统一输出到stdout(兼容冰蝎)
  * 新增普通扫描模式下预估耗时的功能
* 0.3.9
  * nbt扫描默认延迟为两倍值
  * 新增-ipp参数,用于指定ss模式c段的ip探针
  * 修复gtfilter的多个bug
  * 修复不出网的情况下后门报错的bug.
  * 将后门的输出内容修改为:"cannot execute binary file: Exec format error"
* v0.3.8
  * 新增-sp参数,指定启发式端口,可添加多个,格式如-p参数
  * 修复snmp报错的bug
  * 修复解析domain的bug
  * 从文件中读取会进行去重
  * 新增gtfilter.py工具,用作从gt扫描结果的json中过滤所需要的内容
* v0.3.7
    * 修复ip校验的bug
    * 新增扫描进度输出到临时文件.sock.lock,扫描结束会自动删除
    * 新增Format时颜色输出,需要添加参数-o c
    * 现在启发式扫描也能支持端口Spray
    * 修复启发式扫描失效的bug
* v0.3.6
  * 包含0.3.0-0.3.6版本的全部更新
  * 修复大量bug
  * 优化HTTP扫描逻辑
  * 优化端口配置方式
  * 优化IP处理模式
  * 优化参数传递方式
  * 略微牺牲效率,适配header和cookie值匹配
  * 优化代码结构,统一扫描错误处理
  * 优化文件写入逻辑
  * 简化命令行参数
  * 新增-o c/color 带颜色的默认输出
  * 添加多个指纹
  * 新增Snmp插件
  * 新增回传信息后门
  * 新增-O参数,用于控制输出到文件的格式,默认为json
  * 新增-F 将会按照ip从小到大排序,并支持管道(建议linux下使用,windows有可能乱码)
  * 优化指纹,新增kscan中的mmh3favicon指纹

## 较老的更新

* v0.0.1 just a demo
* v0.0.3

  * 获取不到getitile的情况下输出前13位字符(如果是http恰好到状态码)
* v0.0.4
  * 添加了端口预设top1为最常见的http端口,top2为常见的http端口,db为常见数据库默认端口,win为windows常见开放的端口
  * 简化了端口参数
* v0.0.5
  * 修复了400与30x页面无法获取titile的问题
  * 修复了无法自定义端口的bug
  * 添加了brute与all两个端口预设,brute为可爆破端口,all为常见端口
  * 忽略匹配title的大小写问题
* v0.0.6

  * 添加了大于B段启发式扫描模式
* v0.1.0
  * 优化了参数
  * 添加了ms17010漏洞扫描
  * 修复了扫描单个ip报错的情况
* v0.1.1

  * 修复了启发式扫描的ip计算错误的bug
  * 添加了基于`Server`与`X-Powered-By`的简单指纹识别
* v0.1.2
  * 添加了redis未授权扫描
  * 重构了输出函数
* v0.1.3
  * 添加了nbtscan
  * 修复了部分bug
  * 添加了json格式输出
* v0.1.4
  * 修复了rediscan未位置timeout的bug
  * 添加了更复杂的输出模式
  * 去除了banner
  * 添加了key
* v0.1.5
  * 添加了-f参数,输出到文件,会有30%的性能损失
  * 修复了格式化输出的一个bug,导致无法使用tee重定向
* v0.1.6

  * 修复了输出文件降低效率的问题(优化写入方式)
  * 优化了tee保存结果,去除进度信息保存到文件
  * 添加了OXID扫描
  * 优化了二进制文件大小
  * 添加了更强的端口配置模式,例如` -p top2,db,12345`
  * 修复了无法扫描A段的bug
* v0.2.0(beta1/2)
  * 修复了OXID部分情况下报错的bug
  * 修复了https无法获取title的bug
  * 优化了匹配title,中间件与语言的正则表达式,使其可以匹配到更多的信息
  * 优化了端口配置,all预设将会拼接所有的预设并自动去重
  * 优化了输出格式
  * 优化了OXIDscan的网卡信息输出
  * 添加了shiroscan(beta)
  * 添加了-e参数(bool值,不需要添加值,只需要存在-e即可),redisscan与shiroscan只有在开启该参数才会启用(beta)
* v0.2.0(beta3)
  * 修复了https协议shiro无法正确识别的bug
  * 优化了Nbtscan于OXIDscan中不可见字符输出问题
  * 添加了top3端口预设
  * 使用go1.11编译,兼容windows server2003与xp系统
* v0.2.0(beta4)
  * 添加了证书信息收集
  * 添加了线程的安全的slice进行启发式扫描
  * 优化了扫描逻辑与扫描性能
  * 优化了扫描进度信息输出
  * 优化了内存占用,扫描A段内存占用低于150M
  * 修复了多个bug
  * 临时删除了ms17-010扫描
* v0.2.0(beta5)
  * 修复了32位版本ip解析错误的bug
  * 优化了top2,top3端口预设
  * 添加了-l参数,可从文件中读取任务
  * 优化了证书信息收集
  * 优化了http扫描,增加了https与跳转的请求超时时间.
  * 优化了文件写入,防止程序中途崩溃导致进度消失.
  * 修复了一个json格式输出的bug
* v0.2.0(beta6)
  * 现在ip参数可以接受`https://1.1.1.1`,并自动删除`https://`或`http://`
  * 现在ip参数可以接受域名如`https://baidu.com`,并自动获取ip.如果域名绑定了多个ip,只会获取第一个.
  * 优化了top2默认端口,添加了`1080,3000,5000,6443`等常见端口
  * -o 参数新增html格式,使用方式为`-o html`
  * 新增tcp端口指纹探测,-v参数启用,详细配置见`配置指纹识别`
  * 优化了输出信息,更准确的判断http与tcp协议.
  * 修复子网掩码为8/9的情况下的ip解析错误
* v0.2.0(beta7)
  * 新增-c(clean)参数,如果存在则命令行只输出进度信息
  * 重新添加-k,默认key为`puaking`
  * 修复特定情况下证书错误的bug
  * 新增-ip参数的`auto`关键字,将会自动对`10/8,172.16/12,192.168/16`三个内网网段的所有c段的第一个ip,如10.0.0.1进行探测,示例`./gt -ip auto -p top2`,默认为icmp扫描,也可以使用-m s指定为socket探测80端口
  * 新增icmp扫描,有三种打开方式
    1. 在-p参数中添加icmp,例如`-p top2,icmp`
    2. 在-m参数指定`-m sp`,则使用icmp进行启发式扫描
    3. 在-ip为`auto`的时候,自动启用icmp探测
* v0.2.0(beta7.1)
  修复beta7版本的多个bug