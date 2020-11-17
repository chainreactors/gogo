# Getitle
just a weak scanner


## Usage

```
Usage of ./getitle:
  -d int                        超时,默认2s (default 2)
  -ip string            IP地址 like 192.168.1.1/24
  -m string        扫描模式：default or s(smart)
  -p string        ports (default "top1")
  -t int        threads (default 4000)
  -o string     输出格式:clean,full(default) or json
  -f string     输出文件名,默认为空,请用相对路径(./)或绝对路径
  -k string     启动密码(必须输入)为sangfor  

```

### 用法



* 扫描C段的关键端口

`./gt.exe -ip 192.168.1.1/24 -p top2`

* 扫描启发式扫描B段或大于B段

`./gt.exe -ip 172.16.1.1/12 -p top2 -m s`

启发式扫描只会先扫描80端口,如果在该C段中扫描到了80端口,则进行已配置端口的完整扫描.加快扫描速度.

* 端口配置可以使用预设,单端口,和端口段随意组合.例如:

`./gt.exe -ip 172.16.1.1/12 -p top2,db,1000-1009,12345`

* 如果302过多或者扫描结果不稳定,需要增加timeout时间.参数`-d 4`
* 如果网络状态不佳,请视情况减少协程数,默认4000, `-t 1000`指定
* 如果报错uckoff,请输入`-k sangfor`
* 支持nbtscan与OXIDscan.只需要在端口中添加对应的端口,例如:

`./gt.exe -ip 172.16.1.1/12 -p top2,135,137`

* 支持从文件中读取多个任务

ip.txt:

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

扫描外网B段,top2预设端口, smart模式. 耗时

扫描内网172.16.0.0/12段,smart模式,资产较少的情况下耗时10分钟.

如果发现的目标多时间会略微增加.

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
    
      

​    

 ## Todo List

1. 添加NetBIOS  [√]
2. 添加MS17010 [√]
3. 添加OXID [√]
4. 添加简单目录扫描
5. 更灵活的端口模式 [√]
6. 更智能的扫描配置  [√]
7. 重构主要逻辑代码  [√]
8. 添加从文件中读取扫描目标
9. Shiro 100key爆破