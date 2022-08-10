在各种使用场景下, 有不同的输入与输出需求, 非常复杂, 为此gogo还添加了一个python脚本来辅助工作.


因为不断添加需求, 输入与输出也是出bug最多的功能. 现在逻辑上最混乱的也是这个部分.
## 输入
最普通的输入就是命令行, 通过-ip 与-p参数配置任务.

	但在实际情况中, 会有来自其他工具导入的目标, 有来自自身扫描结果的二次输入, 有需要过滤出特定数据的再次输入.  甚至有挂在云函数上的gogo版本.

因此, 目前支持非常多类型的输入. 包括

* 命令行输入
* -l 从文件中读取ip列表,配合其他命令行参数, 同样会自动识别加密解密
* -j 从gogo上一次扫描结果中读取任务,配置其他参数后再次扫描
  * 扫描结果的文件, 自动识别加密并解密
  * 启发式扫描结果的网段文件
  * ip:port:[framework] 按行分割的txt文本
* -L 从标准输入读, 功能同-l参数
* -J 从标准输入读, 功能同-j参数
* -w workflow, 支持名字(逗号分割), base编码的json格式的workflow
* -W 从标准输入读的workflow json格式的文件



	输入的格式也是非常多的, 因为在某个版本引入了输出结果加密, 为了不添加额外的参数, -j参数会自动判断加密,进行解密. 

	还因为stdin遇到/00会中断, 所以从stdin来的数据可能是base64加密过后也可能是明文的,也需要一个自动判断. 这里云函数用这种方式的场景比较多.


	因为架构问题,有一些常见的需求不能通过以上方法直接解决, 就是找到扫描结果中存活的ip扫描其他端口, 看起非常简单, 但是需要两行命令才能解决. 需要配合输出文件来实现.

### workflow
在gt2.0版本后, 引入了全新的命令行操作方式workflow, 大大简化了十几个参数对初学者造成的困扰.

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

例如:`gt -w 10 -p 1-65535 -e -v`

这样原来名字为10的workflow的端口被修改为1-65535, 并开启了version scan与exploit scan.

自定义workflow:

预设的配置文件位于, src/config/workflows.yml, 可以仿照配置文件添加新的预设, 并使用`-w filename` 指定对应的预设.

如果在渗透的远程环境下, 可以使用yaml2json.py 见自定义预设转为base64编码字符串, 使用`-w [BASE64 string]`执行.

## 输出
	在没有配置输出文件的情况下,所有内容会输出到标准输出, 如果指定了-f filename 或者使用-af/-hf自动选择文件名. 则会关闭扫描结果的命令行输出, 只保留进度的命令行输出. 


如果特别想两个地方都保留输出,我也预留了可选项, 使用`-c` 参数能在指定了-f的时候继续保留命令行输出.


如果需要配合其他工具, 那就需要将日志输出关闭,或者不输入到标准输入, 也提供了可选项 `-q`参数关闭所有日志输出.


对于输出的格式, 命令行目前默认是full, 也就是我自定义的全部信息输出, 但是为了配合其他工具, 也提供了各种格式的输出, `-o ip`参数指定需要的字段, 也支持逗号分割的多个参数, `-o ip,port,title`. 以及一些特殊值, 例如`-o url,target`等.


输出到文件的默认是json, 可以通过-O参数进行类似-o参数相同的配置.
并且输出到文件会默认开启加密, 如果想要明文结果. 需要指定-C参数关闭加密, 或者使用-F参数解析.


### 格式化输出
	为了提供各种各样的输出需求, 提供了-F参数对扫描结果进行格式化.
不论是base64, deflate算法压缩后的,还是明文的json,都可以自动解析.

使用: `-F file`

	-F file 会自动解析文件,并整理端口与ip. 输出一个比full可读性更好的结果. 可以实际体验一下, 优化了非常多.

	-F 参数也能指定-o,例如 `-F file -o target` . 也能指定-f输出文件. 甚至能使用-af将hf参数下自动生成的随机文件名再次格式化到正常的文件名.

我以为-F到这里以及圆满了, 后来新的需求又出现了.

	需要将gt扫描结果导入到cobalt strike的target, 将gt扫描结果导出到我们的弱口令爆破工具zombie中. 因此给-o 添加了两个特殊值, `-o zombie`与`-o cs`, 前者需要zombie -gt 读取我的结果, 后则需要gt对应的cs插件解析结果.

	同时, 因为需要针对某些特定服务打poc, 所以还需要一个过滤器 , 又添加了`-filter`参数, 可以通过`-fitler frameworks::weblogic`过滤出对应字段需要的值. 可以添加多个`-filter`依次过滤, 例如 `-filter 7001 -filter frameworks::weblogic` , 其中 `::`是模糊匹配, `==`是全等匹配.


	但是就算如此,还是发现gt内置的过滤器满足不了所有需求, 就添加了gtfilter.py做更多更复杂的过滤. 例如同时过滤多个输出结果的场景. 
例如: `python gtfilter.py file1 file2 -o ip,port -e ip::192.168 -e ip::172.16 -or`  , 从file1与file2中过滤192.168段与172.16段的结果, 输出ip与端口

	但是就算是gtfilter, 也不能解决所有需求, 之后我计划在另一个自动化工具中做更多更复杂的分析工作.




