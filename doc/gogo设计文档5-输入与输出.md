
因为不断添加需求, 输入与输出也是出bug最多的功能. 现在逻辑上最混乱的也是这个部分.
## 输入
最普通的输入就是命令行, 通过-ip 与-p参数配置任务.

但在实际情况中, 会有来自其他工具导入的目标, 有来自自身扫描结果的二次输入, 有需要过滤出特定数据的再次输入.  甚至有挂在云函数上的gogo版本.

因此, 目前支持非常多类型的输入. 包括

* 命令行输入
* -l 从文件中读取ip列表,配合其他命令行参数, 同样会自动识别加密解密
* -j 从gogo上一次扫描结果中读取任务,配置其他参数后再次扫描
  * 结果的文件, 自动识别加密并解密, 也可以输入自行导出的json文件, 只需要保留ip,port, framework三个字段即可.
  * 启发式扫描结果的网段文件
  * ip:port[:framework] 按行分割的txt文本, framework可留空
* -L 从标准输入读, 功能同-l参数
* -J 从标准输入读, 功能同-j参数
* -w workflow, 支持名字(逗号分割), base编码的json格式的workflow
* -W 从标准输入读的workflow json格式的文件

输入的格式也是非常多的, 因为在某个版本引入了输出结果加密, 为了不添加额外的参数, -j参数会自动判断加密,进行解密. 

还因为stdin遇到/00会中断, 所以从stdin来的数据可能是base64加密过后也可能是明文的,也需要一个自动判断. 这里云函数用这种方式的场景比较多.

因为架构问题,有一些常见的需求不能通过以上方法直接解决, 就是找到扫描结果中存活的ip扫描其他端口, 看起非常简单, 但是需要两行命令才能解决. 需要配合输出文件来实现.

### workflow
在gogo2.0版本后, 引入了全新的命令行操作方式workflow, 大大简化了十几个参数对初学者造成的困扰.

可以自定义常用工作流, 或者使用预设的工作流. 参数为-w.

预设的workflow
```
name	index	ip         	port     	mod	ping	arp	smartPort	smartIp	version	exploit	outputFile	outputPath
172noping: 
	0	172.16.0.0/12  	top2,win,db	ss	false	false	default   	default   	0    	none      	auto      	          	          
smart: 
	0	               	top2,win,db	ss	true	true	default   	default   	0    	none      	auto      	          	          
smartnoping: 
	0	               	top2,win,db	ss	false	false	default   	default   	0    	none      	auto      	          	          
192c: 
	0	192.168.0.0/16 	top1      	s	false	false	default   	default   	0    	none      	auto      	          	          
internoping: 
	0	10.0.0.0/8     	top2,win,db	ss	false	false	default   	default   	0    	none      	auto      	          	          
	1	172.16.0.0/12  	top2,win,db	ss	false	false	default   	default   	0    	none      	auto      	          	          
	2	192.168.0.0/16 	top2,win,db	s	false	false	default   	default   	0    	none      	auto      	          	          
smartc: 
	0	               	top1      	sc	false	false	default   	default   	0    	none      	auto      	          	          
c: 
	0	               	top1      	s	false	false	default   	default   	0    	none      	auto      	          	          
interc: 
	0	10.0.0.0/8     	top1      	sc	false	false	default   	default   	0    	none      	auto      	          	          
	1	172.16.0.0/12  	top1      	sc	false	false	default   	default   	0    	none      	auto      	          	          
	2	192.168.0.0/16 	top1      	s	false	false	default   	default   	0    	none      	auto      	          	          
interb: 
	0	10.0.0.0/8     	top1      	ss	false	false	default   	default   	0    	none      	auto      	          	          
	1	172.16.0.0/12  	top1      	ss	false	false	default   	default   	0    	none      	auto      	          	          
	2	192.168.0.0/16 	top1      	ss	false	false	default   	default   	0    	none      	auto      	          	          
10noping: 
	0	10.0.0.0/8     	top2,win,db	ss	false	false	default   	default   	0    	none      	auto      	          	          
192noping: 
	0	192.168.0.0/16 	top2,win,db	s	false	false	default   	default   	0    	none      	auto      	          	          
10: 
	0	10.0.0.0/8     	top2,win,db	ss	true	true	default   	default   	0    	none      	auto      	          	          
172: 
	0	172.16.0.0/12  	top2,win,db	ss	true	true	default   	default   	0    	none      	auto      	          	          
192: 
	0	192.168.0.0/16 	top2,win,db	s	true	true	default   	default   	0    	none      	auto      	          	          
10c: 
	0	10.0.0.0/8     	top1      	sc	false	false	default   	default   	0    	none      	auto      	          	          
192b: 
	0	192.168.0.0/16 	top1      	ss	false	false	default   	default   	0    	none      	auto      	          	          
b: 
	0	               	top1      	ss	false	false	default   	default   	0    	none      	auto      	          	          
inter: 
	0	10.0.0.0/8     	top2,win,db	ss	true	true	default   	default   	0    	none      	auto      	          	          
	1	172.16.0.0/12  	top2,win,db	ss	true	true	default   	default   	0    	none      	auto      	          	          
	2	192.168.0.0/16 	top2,win,db	s	true	true	default   	default   	0    	none      	auto      	          	          
10b: 
	0	10.0.0.0/8     	top1      	ss	false	false	default   	default   	0    	none      	auto      	          	          
172c: 
	0	172.16.0.0/12  	top1      	sc	false	false	default   	default   	0    	none      	auto      	          	          
172b: 
	0	172.16.0.0/12  	top1      	ss	false	false	default   	default   	0    	none      	auto   ```
```

里面的每个参数都可以使用对应的命令行参数进行覆盖, 具体的参数见README.md.

例如:`gogo -w 10 -p 1-65535 -ev`

这样原来名字为10的workflow的端口被修改为1-65535, 并开启了version scan与exploit scan.

自定义workflow:

预设的配置文件位于, v2/templates/workflows.yml, 可以仿照配置文件添加新的预设, 并使用`-w filename` 指定对应的预设.

如果在渗透的远程环境下, 可以使用yaml2json.py 见自定义预设转为base64编码字符串, 使用`-w 'b64de|[BASE64 string]'`执行.

## 输出
在没有配置输出文件的情况下,所有内容会输出到标准输出, 如果指定了-f filename 或者使用-af自动选择文件名(--af格式为`ip_mask_port_mod_type.dat1`). 则会关闭扫描结果的命令行输出, 只保留进度的命令行输出.

如果特别想两个地方都保留输出,我也预留了可选项, 使用`--tee` 参数能在指定了-f的时候继续保留命令行输出.

如果需要配合其他工具, 那就需要将日志输出关闭,或者不输入到标准输入, 也提供了可选项 `-q`参数关闭所有日志输出.

并且输出到文件会默认开启加密, 如果想要明文结果. 需要指定-C参数关闭加密.

### 文件名
如果启用了启发式扫描, 则可能会输出多个文件. 则建议使用`--af`, 分别是
* 带default关键字的扫描结果
* 带ccidr关键字的存活的c段
* 带bcidr关键字的存活的b段
* 带alived关键字的存活的ip

### 格式化输出
为了提供各种各样的输出需求, 提供了-F参数对扫描结果进行格式化.

不论是base64, deflate算法压缩后的,还是明文的json,都可以自动解析.

使用: `-F file`

-F file 会自动解析文件,并整理端口与ip. 输出一个比full可读性更好的结果. 可以实际体验一下, 优化了非常多.

格式化输出时也支持--af, -o, -f等参数, 效果相同.

### 输出格式
对于输出的格式, 命令行目前默认是full, 但是为了配合其他工具, 也提供了各种格式的输出, `-o ip`参数指定需要的字段, 也支持逗号分割的多个参数, `-o ip,port,title`. 以及一些特殊值, 例如`-o url,target`等.

在扫描时可以通过`-o` (输出到命令行的格式, 默认为full)与 `-O` (输出的文件的格式, 默认为json). 分别控制两个输出的格式.

在格式化则, 只有`-o` 生效.

目前gogo支持非常多的输出格式.

* url , `protocol://ip:port` 
* target , `ip:port`
* ip,  ip
* port, 端口
* protocol, 协议
* status, 状态码, 支持别名stat
* host, 证书/主机名等字段
* midware, http中的`Server` header
* language, 语言
* os, 操作系统
* title, 标题
* frameworks, 别名frame, 指纹
* vulns, 别名vuln, 漏洞

可以自由组合, 例如`-o ip,url,title`, 输出格式将会时tab分割的三个字段.

除了这些字段, 还存在一些特殊的输出格式. 如下:
* json, 输出为json, 文件的默认输出格式
* full, 命令行的默认输出格式
* jsonlines,  别名jl, 一行一个json的特殊格式.
* csv, 输出为csv
* color, 带颜色的full输出
* zombie, 导出为zombie的输出格式
* cs, 导出为cobaltstrike中target的格式.

### 过滤器
在很多场景下, 都需要从结果中过滤出特定的目标再次扫描或者导到其他工具中, 因此添加了`--filter` 参数. 

filter可以在三种情况下使用, 分别为.
1. -F result.dat1 , 将从result中过滤特定的结果
2. -j result.dat1 , 不少场景需要再进行一次扫描, 缩减了先-F 在-j的过程, 可以直接在-j中使用--filter
3. 扫描时, 例如`-i 1.1.1.1/24 --filter frame::nginx`, 在扫描时就进行过滤,  被过滤的结果不会输出到命令行, 也不会输出到文件中.

当前支持`==` 全等匹配, `::` 模糊匹配, `!=` 不等于, `!:` 不包含, 四种operator. 

example:

`gogo -F 1.dat --filter frame::weblogic` 过滤weblogic框架

`gogo -F 1.dat --filter port==80` 过滤端口为80的结果

`gogo -F 1.dat --filter title!=` 过滤出标题不为空的结果

filter还支持一些特殊值. 

* `--filter focus` 存在finger中标记为focus的结果
* `--filter vuln` 存在至少一个vuln的结果
