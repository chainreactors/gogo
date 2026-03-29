# gogo TinyGo 兼容改动总览

## 目标

本轮改动的目标不是让 `gogo` 在 TinyGo 下做到与标准 Go 完全等价，而是：

- 产出一个可编译、可运行、可扫描的 TinyGo 版本
- 尽量保留主扫描链路和主输出链路
- 对无法在当前 TinyGo 运行时中稳定修复的功能，明确降级或关闭，并记录原因

当前结果：

- Windows TinyGo 构建成功
- Linux 交叉构建成功
- Windows 本地运行验证成功
- 已验证本地 HTTP 服务扫描可正常输出结果
- `neutron` 模板加载与执行链已在 TinyGo 下恢复

## 已验证结果

### 构建产物

- `dist/gogo_tinygo.exe`
- `dist/gogo_tinygo_linux`

### 已执行验证

- `tinygo build -tags tinygo -o dist/gogo_tinygo.exe ./cmd/tinygo`
- `GOOS=linux GOARCH=amd64 tinygo build -tags tinygo -o dist/gogo_tinygo_linux ./cmd/tinygo`
- `./dist/gogo_tinygo.exe -h`
- `./dist/gogo_tinygo.exe -i 127.0.0.1 -p 18080 -d 1 -D 1 -t 8 -C -v -f dist/tinygo_scan.json -O jl`

本地验证结果包含：

- `protocol=http`
- `status=200`
- `midware=SimpleHTTP/0.6 Python/3.12.7`
- 被动指纹识别可正常输出

## 保留的功能

当前 TinyGo 版本保留了以下核心能力：

- 基础 CLI 启动与参数解析
- IP/端口输入
- 默认扫描链路
- Socket 建连与基础端口探测
- HTTP 基础识别
- 被动指纹识别
- 普通结果输出
- JSONLines 结果文件输出
- Windows 本地运行
- Linux 交叉构建

下列能力代码上仍然保留，但本轮没有单独做完整场景验证：

- 智能扫描模式
- 代理链拨号
- workflow 入口
- 非 HTTP 协议的多种扫描器

## 主仓库改动说明

### 1. 新增 TinyGo 专用入口

新增：

- `cmd/tinygo/main.go`
- `cmd/tinygo/flags.go`

原因：

- 原入口通过 `go-flags` 走 `cmd.Gogo()`，在 Windows TinyGo 下早期运行路径不稳定
- 新入口直接使用 TinyGo 专用参数解析，避免把启动问题和业务逻辑问题耦合在一起

效果：

- `-h`、`--version`、基础扫描参数可正常工作
- 可以单独作为 TinyGo 构建入口使用

### 2. 避免 Windows TinyGo 的栈探针问题

修改：

- `core/core.go`
- `core/init.go`

关键调整：

- `SmartMod(target *utils.CIDR, config Config)` 改为 `SmartMod(target *utils.CIDR, config *Config)`

原因：

- Windows TinyGo 链接阶段曾出现 `___chkstk_ms`
- 根因不是逻辑冲突，而是大对象按值传递造成主路径栈帧过大

效果：

- 规避了 Windows TinyGo 链接阶段的 stack probe 问题

### 3. HTTP/TLS 路径拆分 TinyGo 变体

新增或拆分：

- `pkg/http_tinygo.go`
- `pkg/tls_domains.go`
- `pkg/tls_domains_tinygo.go`
- `pkg/signal_hook.go`
- `pkg/signal_hook_tinygo.go`

原因：

- TinyGo 下 `net/http` 与标准 Go 的能力并不完全等价
- 文件信号处理在 TinyGo 下也不需要沿用标准 Go 实现

效果：

- 主 HTTP 请求链路可运行
- TLS 相关信息采集可以显式降级

### 4. Socket 原始 HTTP 响应改为手工解析

新增：

- `pkg/response_parse.go`
- `pkg/response_parse_tinygo.go`

修改：

- `pkg/collect.go`

原因：

- 在 Windows TinyGo 下，`http.ReadResponse` 会导致运行时崩溃
- `InitScan -> CollectSocketResponse -> parsers.NewResponseWithRaw` 是稳定复现点

处理方式：

- 标准 Go 继续走原有 `parsers.NewResponseWithRaw`
- TinyGo 改成对原始 HTTP 响应做轻量手工解析，只提取主链路需要的字段

效果：

- 默认扫描路径可以稳定跑通
- `status`、`title`、`midware` 等基础字段仍可输出

### 5. Proxy hook 拆出 TinyGo 兼容层

新增：

- `core/proxy_dialer.go`
- `core/proxy_dialer_tinygo.go`

修改：

- `core/runner.go`

原因：

- 早期为了绕开 `neutron/protocols/http` 的 TinyGo 启动期崩溃，`core` 不能在代理注入路径里直接碰 `neutron` HTTP transport

处理方式：

- 标准 Go 继续给 `neutron` HTTP transport 和 `gogo` 自身 transport 一起装配代理拨号器
- TinyGo 仍只给 `gogo` 自身 transport 装配代理拨号器，把 `neutron` 的恢复与代理 hook 解耦

效果：

- `core` 侧不再承担 `neutron` 导入稳定性风险
- `neutron` 模板链可单独修复并重新挂回 TinyGo 主流程

### 6. 通过 netdev 初始化恢复 TinyGo 主机网络能力

新增依赖：

- `github.com/chainreactors/rem/x/netdev`
- `github.com/chainreactors/rem/x/netdev/native`

修改：

- `cmd/tinygo/main.go`

原因：

- 不接入 netdev 时，TinyGo 主机网络路径会报 `Netdev not set`

效果：

- `net.Dial` / `net.DialTimeout` / HTTP 请求可在 TinyGo 下使用
- Windows 本地扫描得以真正执行

## 依赖仓库兼容改动

本次 TinyGo 版本不是只改 `gogo` 本仓库，还依赖了多个上游仓库的本地兼容补丁。

### neutron

改动点：

- 去掉 `publicsuffix-go`
- 去掉 `govalidator`
- HTTP client 拆出 `client_tinygo.go`
- 去掉 `DualStack`
- 缩短过长的模板 struct tag
- `common/dsl` 从 eager `init()` 改为 `sync.Once` 惰性初始化
- `common/utils.go` 去掉 `go-spew/spew` 调试依赖
- `common/NeutronLog` 改为按需获取，避免包级全局直接绑定 `logs.Log`

原因：

- `publicsuffix` / `cookiejar` 链路不适合当前 TinyGo 目标
- 一些第三方依赖或 struct tag 在 TinyGo 下存在编译限制
- `neutron/common` 在 Windows TinyGo 下的真实崩溃点不是模板逻辑本身，而是包导入阶段的全局初始化
- 其中 `common/utils.go` 里的 `spew` 调试链路会让 `neutron/common -> protocols/http -> templates` 在启动时直接触发 `0xC0000409`

### fingers

改动点：

- `common/sender.go` 改为 `!tinygo`
- 新增 `common/sender_tinygo.go`

原因：

- 原 sender 依赖的标准 transport 行为在 TinyGo 下不完全可用
- 需要 TinyGo 专用的最小 sender 实现

### parsers

改动点：

- `http_go1.17.go` 改为 `go1.17 && !tinygo`
- 新增 `http_tinygo.go`

原因：

- TinyGo 下不能依赖标准 Go 那套完整的 `resp.TLS` 行为

### utils

改动点：

- `ParseHostToIP` 改为走 `resolveHostIP`
- 新增 `dns_lookup_tinygo.go`

原因：

- TinyGo 下 DNS 能力需要单独降级处理

## 已恢复与仍降级的功能

下面这些功能分成两类：

- 已经定位根因并恢复
- 仍然保留降级，因为继续硬修的收益暂时不够高

### 1. Neutron 漏洞利用链

当前状态：

- TinyGo 版本下已恢复

涉及文件：

- `pkg/load_neutron_tinygo.go`
- `engine/neutronScan_tinygo.go`
- `neutron/common/dsl/dsl.go`
- `neutron/common/utils.go`

恢复原因：

- 在 Windows TinyGo 下，`github.com/chainreactors/neutron/common` 单独导入即可稳定触发 `0xC0000409`
- 继续拆分后确认 `common/dsl` 单独导入不崩，真正的启动期崩溃来自 `common/utils.go` 的调试依赖 `github.com/davecgh/go-spew/spew`
- 移除 `spew` 后，`protocols/http`、`templates`、最终 `gogo` TinyGo 主程序都恢复正常启动
- `common/dsl` 的惰性初始化一起保留，避免大批 DSL helper 在导入时一次性注册

结论：

- `neutron` 被放弃的根因已经找到，属于包导入阶段的全局/调试初始化问题，不是模板执行模型本身不可修
- TinyGo 版本现在重新使用真实模板加载与执行链，而不是 stub

本轮结果：

- 恢复 `neutron` 模板加载
- 恢复 `neutron` 扫描执行
- `gogo_tinygo` 已通过 `-h`、最小导入探针、本地 HTTP 扫描验证

### 2. FingerPrintHub active matching

当前状态：

- TinyGo 版本下已关闭

涉及文件：

- `pkg/load_common_tinygo.go`
- `engine/httpFingerScan_tinygo.go`

放弃原因：

- `github.com/chainreactors/fingers/fingerprinthub` 在 Windows TinyGo 下单独导入时会直接触发运行时崩溃 `0xC0000409`
- 崩溃发生在业务逻辑之前，属于运行时级别不稳定，不适合继续挂在主扫描链路上

因此本轮选择：

- 保留普通 `fingers` 被动识别
- 关闭 FingerPrintHub 的 active matching

### 3. Extractor 加载

当前状态：

- TinyGo 版本下已关闭内置 extractor 编译与加载

涉及文件：

- `pkg/load_common_tinygo.go`

放弃原因：

- `LoadExtractor()` 在 TinyGo Windows 下是可稳定复现的崩溃点
- 崩溃发生在初始化阶段，尚未进入扫描主逻辑
- 当前判断与正则编译链或相关标准库行为有关

因此本轮选择：

- TinyGo 版本将 extractor 初始化降级为空实现
- 保证扫描主流程优先可用

### 4. TLS 证书域名提取

当前状态：

- TinyGo 版本下关闭

涉及文件：

- `pkg/tls_domains_tinygo.go`

放弃原因：

- TinyGo 下 HTTPS/TLS 元数据路径与标准 Go 不等价
- 本轮目标是先让 HTTP/Socket 主链路稳定，不继续在 TLS 元数据上深挖

因此本轮选择：

- 保留 HTTP 服务识别
- 关闭证书域名提取和相关 TLS 细节收集

## 兼容思路总结

本轮 TinyGo 兼容策略不是“把所有功能都修到完整”，而是按以下优先级做裁剪：

1. 先保证能编译
2. 再保证能启动
3. 再保证能扫描
4. 最后才恢复高阶能力

因此优先保留了：

- CLI
- 主扫描链路
- HTTP 基础识别
- 被动指纹
- 文件输出

优先放弃了：

- exploit 执行
- FingerPrintHub active match
- extractor
- TLS 元数据提取

这几项都不是语义性小问题，而是已经定位到会导致 TinyGo Windows 运行时崩溃或初始化崩溃的链路。

## 后续可继续推进的方向

如果后面还要继续恢复功能，建议按下面顺序推进：

### 优先级 1

- 继续拆 `neutron/protocols` 与 `neutron/templates` 的导入树
- 找到具体导致 `0xC0000409` 的子包或全局初始化

### 优先级 2

- 恢复 extractor
- 重点排查正则编译链与 TinyGo Windows 的兼容问题

### 优先级 3

- 恢复 FingerPrintHub active matching
- 先缩小到最小 import graph，再逐步回挂到 `HTTPFingerScan`

### 优先级 4

- 评估是否把 `rem/x/netdev` 内联到 `gogo`，减少对 `rem` 的外部依赖
