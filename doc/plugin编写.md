## description
gogo 保留了大量可拓展接口, 例如指纹, poc/exp, 工作流, 端口.

这些预设保存在`v2/templates`目录下, 以yaml的形式保存与编辑, 但在编译的时候会自动转为json并压缩打包到二进制文件中.

绝大部分插件都可以使现有的框架能完成, 如果有较为复杂的需求, 例如ms17010探测. 可以在`/v2/internal/plugin`中添加.

## 端口
配置文件: `v2/templates/port.yaml`

端口配置最为简单, 不需要讲解就能理解. 默认配置中有大量案例, 如果有新的默认端口预设, 可以提交issue或pr, 或者通过社交软件联系我.

值得一提的是, `name`与`tags` 都会被gt作为-p参数下可选择的预设, 例如db预设, 就是通过tags的方式给多组端口都加上了这个tag. 通过-p db 即可选用所有的数据库默认端口.

一个完整的示例

```yaml
- name: top2
  ports:
    - '70'
    - 80-90
    - '443'
    - '1080'
    - 2000-2001
    - 3000-3001
    - '1443'
    - '4443'
    - '4430'
    - 5000-5001
    - '5601'
    - 6000-6003
    - 7000-7003
    - 9000-9003
    - 8080-8091
    - 8000-8020
    - '8820'
    - '6443'
    - '8443'
    - '9443'
    - '8787'
    - '7080'
    - '8070'
    - '7070'
    - '7443'
    - 9080-9083
    - '5555'
    - '6666'
    - '7777'
    - '9999'
    - '6868'
    - '8888'
    - '8889'
  type:
    - http
    - common
```

这样配置的端口可通过`-p top2` 或`-p http` 或`-p common`三种方式调用

可以在指纹中的`default_port`字段填写port中配置的name或tag
## 指纹
指纹分为tcp指纹, http指纹

tcp指纹与http指纹为同一格式, 但通过不同的文件进行管理

### tcp指纹/http指纹
配置文件: `v2/templates/http/*` 与 `v2/templates/tcpfingers.yaml`

一个完整的配置:
```yaml
- name: frame   # 指纹名字, 匹配到的时候输出的值
  default_port: # 指纹的默认端口, 加速匹配. tcp指纹如果匹配到第一个就会结束指纹匹配, http则会继续匹配, 所以默认端口对http没有特殊优化
    - '1111'
  protocol: http  # tcp/http, 默认为http
  rule:
   - version: v1.1.1, 可不填, 默认为空, 表示无具体版本
     regexps: # 匹配的方式
        vuln: # 匹配到vuln的正则, 如果匹配到, 会输出framework为name的同时, 还会添加vuln为vuln的漏洞信息
          - version:(.*) # vuln只支持正则,  同时支持版本号匹配, 使用括号的正则分组. 只支持第一组
        regexp: # 匹配指纹正则
          - "finger.*test" 
       # 除了正则, 还支持其他类型的匹配, 包括以下方式
        header: # 仅http协议可用, 匹配header中包含的数据
          - string
        body: # 包含匹配, 非正则表达式
          - string
        md5: # 匹配body的md5hash
          - [md5]
        mmh3: # 匹配body的mmh3hash
          - [mmh3]
          
        # 只有上面规则中的至少一条命中才会执行version
        version: 
          - version:(.*)  # 某些情况下难以同时编写指纹的正则与关于版本的正则, 可以特地为version写一条正则

     favicon: # favicon的hash值, 仅http生效
        md5:
          - f7e3d97f404e71d302b3239eef48d5f2
        mmh3:
          - '516963061'
     level: 1      # 0代表不需要主动发包, 1代表需要额外主动发起请求. 如果当前level为0则不会发送数据, 但是依旧会进行被动的指纹匹配.
     send_data: "info\n" # 匹配指纹需要主动发送的数据
     vuln: redis_unauthorized # 如果regexps中的vuln命中, 则会输出漏洞名称. 某些漏洞也可以通过匹配关键字识别, 因此一些简单的poc使用指纹的方式实现, 复杂的poc请使用-e下的nuclei yaml配置

```

为了压缩体积, 没有特别指定的参数可以留空会使用默认值.

在两个配置文件中包含大量案例, 可以参考.

todo: 从nmap中移植更多常见的tcp指纹

## workflow

配置文件: `v2/templates/workflows.yaml`

一个完整的示例, 
```yaml
- name: "192"         // 名字, 可通过-w调用的标识符
  description: "对192.168.1.1/16使用完整的启发式扫描" // 描述
  ip: 192.168.0.0/16  // 指定的ip
  iplist:             //指定的ip列表, 与ip二选一
    - 192.168.0.0/16 
  ports: top2,win,db  // 端口配置, 与命令行用法相同, 默认值 'top1'
  mod: s              // 模式, 与命令行用法相同, 默认值 'default'
  ping: true          // ping启发探测,等同于命令行的--ping 默认值 'false'
  no-scan: false      // 设置为true则只进行启发式扫描, 不会进行端口扫描. 默认值 'false', 等同于命令行--no
  ip-probe: default    // ip探针, 只可使用于-m ss的场景下, 默认值 'default', 等同于命令行的--ipp default
  port-probe: default  // 端口探针, 只可使用于启发式扫描场景下, 默认值 'default', 等同于命令行的--sp default
  exploit: none       // 是否启用漏扫, 默认值 'none', 等同于命令行的-e 或 -E  
  verbose: 0          // 是否启用主动指纹识别, 默认值 '0', 等同于-v
  file: auto          // 输出文件位置, 默认值 'auto', 等同于-f
  path: .             // 输出文件路径, 默认值 '.', 等同于--path
  tags:               // 将多个name划分为组, 可通过-w tagname即可调用多个workflow
    - inter
```

如果没有填相应的值,则采用默认值. 

如果使用-w参数, 但只想改变某几个参数, 可直接使用-w workflowname的同时, 使用命令行参数进行覆盖, 命令行参数的优先级大于workflow.

## poc 
poc 编写相对复杂, 与nuclei 大致相同, 但因为版本落后nuclei最新版, 因此并不是100%的完全兼容.

详情见[poc编写](poc编写.md)

## plugin

每个端口探测生命周期有一个贯穿始终的result变量, 在dispatch中添加触发某个插件的逻辑, 并在插件的具体实现中修改result变量即可完成插件的编写. 

没有做过多的抽象, 希望最核心的可拓展能力还是以yaml的dsl为主. 

一个简单的例子, `v2/pkg/plugin/wmiScan.go`

```go
func wmiScan(result *pkg.Result) {
	result.Port = "135"
	target := result.GetTarget()
	conn, err := pkg.NewSocket("tcp", target, RunOpt.Delay)
	if err != nil {
		return
	}
	defer conn.Close()

	result.Open = true
	ret, err := conn.Request(data, 4096)
	if err != nil {
		return
	}

	off_ntlm := bytes.Index(ret, []byte("NTLMSSP"))
	if off_ntlm != -1 {
		result.Protocol = "wmi"
		result.Status = "WMI"
		tinfo := utils.ToStringMap(ntlmssp.NTLMInfo(ret[off_ntlm:]))
		result.AddNTLMInfo(tinfo, "wmi")
	}
}
```

没有做过多的包装, 只需要多result的一些属性做出修改, 即可完成一个简易的poc. 

大部分常见的特殊端口都已经覆盖, 如果额外的需求可以在新建issue. 更建议使用者协助我们维护[gogo-templates](https://github.com/chainreactors/gogo-templates) 仓库.






