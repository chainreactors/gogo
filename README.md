# Getitle
一个资产探测扫描器. 设计之初为在内网中对A段进行可接受时间内(大约八小时,睡一觉的时间)的资产探测. 开发完成后发现对外网资产探测同样好用.

## Usage

```
Usage of ./getitle:
  -d int       超时,默认2s (default 2)
  -ip string   IP地址 like 192.168.1.1/24
  -m string    扫描模式：default or s(smart)
  -p string    ports (default "top1")
  -t int       threads (default 4000)
  -o string    输出格式:clean,full(default) or json
  -f string    输出文件名,默认为空,请用相对路径(./)或绝对路径
  # -k string    启动密码(必须输入)为sangfor  
  -l string    从文件中读取任务,例如:-l ip.txt

```



端口预设(v0.2.0 beta4):

```
	case "top1":
		ports = []string{"80", "443", "8080"}
	case "top2":
		ports = []string{"80-90", "443", "4443", "7000-7009", "9000-9009", "8080-8090", "8000-8020", "8443", "8787", "7080", "8070", "7070", "9080", "5555", "6666", "7777", " 9999", "8888", "8889", "9090", "8091", "8099", "8848", "8060", "8899", "800", "801", "10000", "10080", "10800"}
	case "top3":
		ports = []string{"4430", "9443", "6080", "9091", "8100-8110", "8021-8030", "8880-8890", "8010-8020", "8090-8100", "8180-8181", "8800", "8761", "8873", "8866", "8900", "8282", "8999", "8989", "8066", "8200", "8111", "8030", "8040", "8060", "8180"}
	case "db":
		ports = []string{"3306", "3307", "1433", "1521", "5432", "6379", "11211", "27017"}
	case "rce":
		ports = []string{"1090", "1098", "1099", "4444", "11099", "47001", "47002", "10999", "45000", "45001", "8686", "9012", "50500", "4848", "11111", "4445", "4786", "5555", "5556"}
	case "win":
		ports = []string{"21", "22", "23", "53", "88", "135", "137", "139", "389", "445", "1080", "3389", "5985"}

```



### 用法

因为并发过高,性能限制主要来自路由器设备.因此**建议在阿里云,华为云等vps上使用**,如果扫描国外资产,建议在国外vps上使用.本地使用如果网络设备性能不佳会带来大量丢包.

如果使用中发现疯狂报错,大概率是io设备问题(例如多次扫描后io没有被正确释放,或者配合proxifier以及类似代理工具使用报错),可以通过重启电脑,或者虚拟机中使用,关闭代理工具解决.如果依旧无法解决请联系我们.

一般情况下无法在代理环境中使用,除非使用-t参数指定较低的速率(默认协程池上线为4000).

* 扫描C段的关键端口

`./gt.exe -ip 192.168.1.1/24 -p top2`

* 扫描启发式扫描B段或大于B段

`./gt.exe -ip 172.16.1.1/12 -p top2 -m s`

启发式扫描只会先扫描80端口,如果在该C段中扫描到了80端口,则进行已配置端口的完整扫描.加快扫描速度.

* 端口配置可以使用预设,单端口,和端口段随意组合.例如:

`./gt.exe -ip 172.16.1.1/12 -p top2,db,1000-1009,12345`

当前top2预设约90个端口,top2+top3约140个端口,主要从来内外网http资产探测.

* 如果302过多或者扫描结果不稳定,需要增加timeout时间.参数`-d 4`
* 如果网络状态不佳,请视情况减少协程数,默认4000, `-t 1000`指定
* 如果报错fuckoff,请输入`-k sangfor`
* 支持nbtscan与OXIDscan.只需要在端口中添加对应的端口,例如:

`./gt.exe -ip 172.16.1.1/12 -p top2,135,137`

* 支持从文件中读取多个任务

配置文件格式ip.txt:

```
47.95.116.67/24 top2
121.36.32.125/16 db smart
```

`./gt.exe -l ip.txt`



### 实验性功能:

-e参数开启简单的漏洞探测.

当前只支持redis未授权,shiro key发现,ms17-010(免杀原因临时移除)

`./gt.exe -ip 172.16.1.1/12 -p top2,445  -e`





### v0.2.0(beta4)版本性能参考:

配置: win10 超时2s,协程数4000

扫描外网C段,top2预设端口(共70个端口). 耗时10s

扫描外网B段,top2预设端口, smart模式. 耗时3分钟

扫描内网172.16.0.0/12段,smart模式,资产较少的情况下耗时10分钟.

如果发现的目标多时间会略微增加.

当前`getitle`扫描准确度与速度以及能获取的信息量均优于Serverscan,allin等扫描器.

## Makefile

 * make release VERSION=VERSION to bulid getitle to all platform

 * Windows build muli releases

   ```
   go get github.com/mitchellh/gox
   gox.bat
   ```

   

## Change Note

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

​    

 ## Todo List

1. 添加NetBIOS  [√]

2. 添加MS17010 [√]

3. 添加OXID [√]

4. 添加简单目录扫描 (将在新的工具中实现,gt主要进行资产探测)

5. 更灵活的端口模式 [√]

6. 更智能的扫描配置  [√]

7. 重构主要逻辑代码  [√]

8. 添加从文件中读取扫描目标  [√]

9. 添加常见服务指纹识别

   