## description
gogo 保留了大量可拓展的接口, 例如指纹, poc/exp, 工作流, 端口.

这些预设保存在`v1/config`目录下, 以yaml的形式保存与编辑, 但在编译的时候, 通过`updateconfig.py`自动将yaml转为压缩后的json格式. 兼顾方便与性能.

## 端口
配置文件: `v1/config/port.yaml`

端口配置最为简单, 不需要讲解就能理解. 默认配置中有大量案例, 如果有新的默认端口预设, 可以提交issue或pr, 或者通过社交软件联系我.

值得一提的是, `name`与`type` 都会被gt作为-p参数下可选择的预设, 例如db预设, 就是通过type的方式给多组端口都加上了这个tag. 通过-p db 即可选用所有的数据库默认端口.

## 指纹
指纹分为tcp指纹, http指纹, md5指纹, mmh3指纹.

tcp指纹与http指纹为同一格式, md5与mmh3指纹为同一格式
### tcp指纹/http指纹
配置文件: `v1/config/httpfingers.yaml` 与 `v1/config/tcpfingers.yaml`

一个完整的配置:
```
- name: redis   # 指纹名字, 匹配到的时候输出的值
  level: 1      # 0代表不需要主动发包, 1代表需要额外主动发起请求. 如果当前level为0则不会发送数据, 但是依旧会进行被动的指纹匹配.
 
  default_port: # 指纹的默认端口, 加速匹配. tcp指纹如果匹配到第一个就会结束指纹匹配, http则会继续匹配, 所以默认端口对http没有特殊优化
    - '6379'
  protocol: tcp  # tcp/http, 默认为http
  rule:
   - regexps: # 匹配的方式
        vuln: # 匹配到vuln的正则, 如果匹配到, 会输出framework为name的同时, 还会添加vuln为vuln的漏洞信息
          - redis_version:(.*) # vuln只支持正则,  同时支持版本号匹配, 使用括号的正则分组. 只支持第一组
        regexp: # 匹配指纹正则
          - "-NOAUTH" 
          - "-ERR"
          - "-DENIED"

       # 除了regexp, 还支持其他类型的匹配, 包括以下方式
        header: # 仅http协议可用, 匹配header中包含的数据
          - string
        body: # 包含匹配, 非正则表达式
          - string
        md5: # 匹配body的md5hash
          - [md5]
        mmh3: # 匹配body的mmh3hash
          - [mmh3]
        send_data: "info\n" # 匹配指纹需要主动发送的数据, 只有当前level设置为1才会生效
        vuln: redis_unauthorized # 某些漏洞也可以通过匹配关键字识别, 因此一些简单的poc使用指纹的方式实现, 复杂的poc请使用-e下的nuclei yaml配置
  
```

为了压缩体积, 没有指定的参数会设置默认值.

在两个配置文件中包含大量案例, 可以参考.

todo: 从nmap中移植更多的tcp指纹

### md5/mmh3 指纹
配置文件: `v1/config/md5fingers.yaml` 与 `v1/config/mmh3fingers.yaml`


对于favicon的指纹识别, 做了特殊的优化, 使用md5/mmh3哈希表进行识别. 

可以使用httpx快速计算md5,mmh3 hash值, `echo [url]/favicon.ico | httpx -hash md5,mmh3`

## workflow
配置文件: `v1/config/workflows.yaml`



