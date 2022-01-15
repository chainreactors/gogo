
<br />端口扫描器在今天也有非常多的分支了, 面向不同的用户不同的场景不同的环境. 

- 有专注于端口开放情况的MX1014(TCP), masscan(SYN) 
- 有传统的老牌全能扫描器nmap
- 有自定义传输层协议的扫描器sx, naabu
- 以及这两年很火的各种缝合怪扫描器: fscan,kscan,yasso等等
- 刚出来的内网网段探测扫描器, netspy

还有非常多细枝末节的扫描器.<br />而getitle的定位则是内网的网段探测,端口探测, 指纹识别与poc验证. 抛弃了各种服务弱口令爆破的功能.<br />原因是 端口探测, 指纹识别与poc验证 实际上是一条流水线上的工作, 逻辑上前后连续一致, 甚至不会带来多大的性能负担. 各种服务的弱口令则引入了不一致性, 需要新增很多配置参数, 引入很多库, 引入各种各样的代码. 因此,弱口令爆破这一块,将独立实现.<br />本文将描述getitle设计中需要解决的问题,以及解决的方案. <br />​<br />
<a name="CeG9F"></a>
## 快
在对一些常见的扫描器调研之后以及对编程，网络的原理学习之后，发现快并非是线程数越高越好。要达到快还有很多限制条件以及对应的解决方案。
<a name="oAnlG"></a>
### 并发
最常见的解决方案就是提高线程数，例如早期扫描器多是单线程，或者10，20的线程数，例如御剑，python开发的一些扫描器以及一些国外的简单发包工具。 虽然他们支持多线程，但是对高线程数的支持并不好。原因可能在于当年协程这一概念没有广泛使用，也有可能是生态中没有简单的解决方案。使用系统的多线程API，将会在多个方面带来大量额外的性能消耗。

1. 需要在内核层与用户层不断切换
1. 不断还原与保存高达4M的线程堆栈
1. 为了线程安全使用的各种锁带来的耗时

。。。以及一些我尚不知道的性能消耗，导致多线程的应用很难进行数百甚至数千线程的并发。<br />在2021年的今天，go提供了简单可靠方便的高并发解决方案，可以在一核2G的低配VPS上实现数千个goroutine的调度。只需要使用go函数，就能随意的实现数千个协程的并发，协程的调度将由go进行，不再需要系统调度的大量无用消耗。<br />当然，go的协程调度也不是无损，为了减少这个消耗，我们可以采用复用协程池的方式尽可能的减少消耗.<br />

<a name="VD6ag"></a>
### 网络
<a name="JTuMu"></a>
#### tcp拥塞控制
都学过tcp有拥塞控制, 但是这个拥塞控制是针对每一条tcp信道自身的,不会影响到其他tcp信道. 因此只有在传输大数据的时候,才会有性能影响. 对于端口扫描这样的场景, 每条tcp信道并不会有非常多的数据交互, 因此不受tcp拥塞控制影响. 但是网络拥塞会确确实实的影响到扫描准确率. 这是因为刚才提到的路由器的问题, 在路由的过程中, 网络拥塞 每个ttl的时间就会增加.<br />所以判断网络是否拥塞,可以判断ttl耗时的变化.  
<a name="njI02"></a>
#### 路由器的tail drop
在测试扫描的过程中, 有几次把家里的华为路由器打挂了, 直接重启了.<br />后来才知道, 扫描的限制可能不来自代码, 也不来自系统, 而是路由器. 如果路由器网络拥塞了, 会采用tail drop(丢到队列末尾的数据包)来告诉客户端的tcp拥塞了,启用tcp拥塞控制,慢点发包. 而如果再负载再大一点, 路由器可能会直接重启. 重启这种问题主要再家用路由器上, 企业级路由器面对几千的并发还是没有任何问题的.
<a name="Qj2MH"></a>
#### tcp keep-alive
http1.1中,实现了keep-alive,不再需要每次http重写建立一次握手,浪费大量资源. <br />因此在http端口扫描,指纹识别,以及打poc的过程中, 都可以利用这个keep-alive长连接.<br />但是对于tcp端口, 则不适用这个keep-alive, 因为某些服务, 只有第一个包正确了才会返回对应的信息, 否则要么server主动断开连接,要么不再返回信息. 所以每个tcp端口扫描都建议重新建立连接.
<a name="Krf37"></a>
#### time-wait
time-wait状态代表着tcp连接已经关闭, 但是fd还被占用,等待可能的后续数据处理, 防止有包迷失在网络中被污染下一个使用这个端口的fd.<br />如果不能正确的处理这个问题, 可能导致fd与端口资源耗尽.<br />​<br />
<a name="GxExP"></a>
### 系统限制
<a name="P5dl2"></a>
#### windows 线程调度
windows 的线程调度性能显然不如linux. 这里指的不只是并发控制, 还有tcp堆栈以及其他各种各样的消耗.<br />在使用windows进行扫描的时候, 经常会导致网络崩溃, 需要好几分钟才能回复. 或者是产生非常大量的漏报, 或者是识别不到http协议,只能建立tcp握手等等问题<br />在windows进行扫描遇到了非常多的信息, 最终只能降低线程数妥协windows.<br />​<br />
<a name="Pfroz"></a>
#### 最大fd限制
老版本的linux默认的fd限制为1024, 部分新版本的linux发行版改成了65535, 如果要修改需要root权限指定`limits -n 65535`修改.<br />windows中也有类似的限制, 默认大概是5000, 需要修改注册表修改, 万幸(带引号)的是windows大部分情况根本跑不到4000网络就崩溃了.<br />​<br />
<a name="y9ilS"></a>
#### 65535最大端口数限制
每个系统可用的端口都只有65535个, 而在http扫描的时候, 部分语言,例如go带复用连接池,自动开启keep-alive, 导致端口被长时间占用, 不能正确的松开. 其他一些语言,例如C#也有类似问题.<br />​<br />
<a name="KKoEX"></a>
#### icmp rate limit
todo<br />

<a name="y1Gd0"></a>
### 编程与算法
影响扫描效率的不仅仅外在的工具与环境, 还有很大一部分来自编程人员自己.<br />例如滥用锁可能导致性能降低不少. 一次大的内网扫描, 可能会进行数千万次的扫描, 锁多了时间的堆积也是可观的数字.<br />再例如不正确的数据结构, 例如fscan, 在favicon匹配的时候,采用的是数组for循环, 而实际上, 采用hash表可以提速不少.<br />
<br />不过这一块我也是初学者,也在尽可能的提高自己的代码质量和算法, 因此给不了太多建议.<br />可以阅读[https://github.com/projectdiscovery](https://github.com/projectdiscovery) 团队的代码,我从中学习了很多go开发的技巧与设计.<br />

<a name="Rysez"></a>
## 可拓展
为了可拓展性, xray采用了强依赖dsl编写poc, 导致poc很难移植. 部分python poc框架, 例如pocsuite则是直接采用python编写代码, 更难迁移到其他平台. goby提供了一个图形化的poc生成工具, 方便了不少, 不过并不开源面向社区.<br />getitle也在尽可能的追求可拓展性. 目前可通过配置文件拓展的功能有很多, 一一解释:
<a name="a1Z2h"></a>
### 端口预设
通过tag进行多对多的端口管理, 可以给服务的多个默认端口打上服务的tag, 再给多个服务打上使用场景的tag. <br />可以在yaml中自由的配置, 在编译过程中生成对应的代码.<br />例如mysql的端口预设:
```
- name: mysql
  ports:
    - 3306-3308
  type:
    - db
    - brute
```
可以通过`-p mysql`指定, 也可以通过`-p db` 或 `-p brute`, 当然也可以使用`-p 3306-3308`. 任意的组合.<br />通过给某一大类的服务,例如数据库都打上db的tag ,可以快速配置需要扫描的端口.<br />目前getitle已经收集了数百个默认端口以及对应的服务.<br />​<br />
<a name="o19q4"></a>
### 启发式内网扫描预设
这是一个面向启发式扫描的预设配置. 通过`-m a`调用预设, 自动测绘常见保留地址.<br />​

-P inter查看默认配置. 
```
CIDR           				 MOD     PortProbe       IpProbe
200.200.0.0/16          s       icmp    all
10.0.0.0/8              ss      icmp    1
172.16.0.0/12           ss      icmp    1
192.168.0.0/16          s       80      all
100.100.0.0/16          s       icmp    all
```
<a name="tICWb"></a>
### 指纹
gt的指纹配置文件分为了四大块,分别是

1. http指纹
```
- name: tomcat
  protocol: http
  level: 0
  vuln: Directory traversal
  regexps:
    vuln:
      - Directory Listing For
    regexp:
      - "<h3>Apache Tomcat/(.*)</h3>"
      - "<title>Apache Tomcat/(.*)</title>"
    header:
      - Apache-Coyote
```
这个可以提取tomcat版本号, 目录遍历漏洞, 非404页面的tomcat指纹匹配等等.<br />这种灵活的配置在多次项目中有奇效, 扫到了一些正常指纹识别抓不到的指纹,例如302页面跳转时location的指纹. 

2. tcp指纹
```
- name: redis
  level: 1
  vuln: redis_unauthorized
  default_port:
    - '6379'
  protocol: tcp
  send_data: 'info\n'
  regexps:
    vuln:
      - redis_version:(.*)
    regexp:
      - "-NOAUTH"
      - "-ERR"
      - "-DENIED"
```

3. favicon md5 hash指纹
3. favicon mmh3 hash指纹

只需要编写yaml就能快速配置一个相对来说复杂的指纹识别. 并且不仅限于指纹识别, 一些简单的漏洞探测都可以在这里完成配置.<br />​<br />
<a name="d0GV1"></a>
### 漏洞探测
我选用了目前最活跃的社区,也是代码质量相对较高, 最关键的poc可快速配置的工具nuclei.<br />当然, nuclei本身支持更加复杂的漏洞探测, 例如headless, 条件竞争漏洞, 需要dnslog/httplog的漏洞探测, dsl等等, 这些功能在内网并不实用, 所以我阉割了部分功能,只保留最关键的tcp与http漏洞探测.<br />对于大部分情况,已经够用了, 可以快速用nuclei社区移植poc到getitle中. 但是为了防止大量无效poc污染扫描结果, 我选择人工筛选poc.<br />​

示例: 编写一个weblogic弱口令的poc
```
id: weblogic-weak-pass

info:
  name: WebLogic weak login
  author: pdteam
  severity: high
  tags: weblogic-console

requests:
  - raw:
      - |
        POST /console/j_security_check HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/x-www-form-urlencoded
        Referer: {{BaseURL}}/console/login/LoginForm.jsp

        j_username={{username}}&j_password={{password}}&j_character_encoding=UTF-8
    attack: pitchfork
    payloads:
      username:
        - weblogic
        - weblogic
        - weblogic
        - weblogic
        - weblogic
        - admin
        - admin
        - system

      password:
        - weblogic
        - weblogic1
        - welcome1
        - Oracle@123
        - weblogic123
        - 12345678
        - security
        - password

    stop-at-first-match: true
    cookie-reuse: true
    matchers-condition: and
    matchers:
      - type: word
        part: header
        words:
          - "ADMINCONSOLESESSION"
        condition: and

      - type: word
        part: header
        negative: true
        words:
          -  LoginForm.jsp
        condition: and

      - type: status
        status:
          - 302
```
从nuclei社区中直接复制就可以. 因为阉割了dsl, 如果nuclei的poc中使用的是dsl, 需要手动替换成静态的配置.<br />可以看到nuclei支持raw http的解析, 因此, 可以从burp中复制包生成poc. 下一阶段的目标是实现大部分内网常见设备的默认口令自动化.<br />
<br />
<br />对于这些配置文件, 我采用的是python脚本压缩加密后再生成go代码, 而不是fscan这样嵌入资源文件. 一是文件体积的考虑,二是隐蔽性.<br />​

因为工作原因, 暂时不能开源面向社区收集poc,端口与指纹, 所以有需要的拓展可联系我, 一起添加对应的功能.
