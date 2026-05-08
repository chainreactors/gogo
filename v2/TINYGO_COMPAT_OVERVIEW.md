# gogo TinyGo 兼容改动与功能取舍总览

## 1. 文档目的

这份文档记录当前 `gogo` 为适配 TinyGo 所做的兼容性改动，以及哪些功能被显式降级、放弃，或者只在特定构建模式下保留。

目标不是追求与标准 Go 版本完全等价，而是：

- 保持 TinyGo 版本可构建、可运行、可扫描
- 尽量保留核心扫描链路
- 对无法等价实现的功能明确记录原因和边界

本文档描述的是当前代码状态，不再保留早期排障阶段已经过时的结论。

## 2. 当前默认 TinyGo 构建状态

当前推荐入口：

- [build-tinygo.sh](/D:/Programing/go/chainreactors/gogo/v2/scripts/build-tinygo.sh)
- [cmd/tinygo/main.go](/D:/Programing/go/chainreactors/gogo/v2/cmd/tinygo/main.go)

当前默认构建特征：

- 默认 profile: `release`
- 默认 tags: `tinygo forceposix noembed osusergo netgo`
- 默认启用 patched TinyGo toolchain
- 默认保留 embedded templates，不会默认走 `emptytemplates`
- 默认在可用时执行 `strip` 和 `upx --best --lzma`

已经完成的验证：

- `gogo/v2` 执行 `go test ./...` 通过
- `fingers` 执行 `go build ./fingerprinthub` 通过
- `neutron` 执行 `go build ./common ./protocols/http` 通过
- `bash scripts/build-tinygo.sh -o dist/gogo_tinygo_smoke.exe` 通过
- 本地 HTTP 靶标验证通过：
  - 指纹识别成功
  - `-e auto` 的 neutron 探测成功
  - `-E CVE-2021-29441` 的强制模板执行成功

## 3. 主仓库兼容性改动

### 3.1 TinyGo 专用入口与网络初始化

涉及文件：

- [main.go](/D:/Programing/go/chainreactors/gogo/v2/cmd/tinygo/main.go)
- [flags.go](/D:/Programing/go/chainreactors/gogo/v2/cmd/tinygo/flags.go)

改动目的：

- 避免直接复用标准 Go 入口时引入不必要的启动路径差异
- 在 TinyGo 启动时显式注册 `rem/x/netdev/native`

效果：

- TinyGo 版本能够在主机环境下正常使用 `net.Dial`、HTTP 请求和扫描主链路
- 解决了未注册 netdev 时的 `Netdev not set` 问题

### 3.2 自动化 patched toolchain

涉及文件：

- [build-tinygo.sh](/D:/Programing/go/chainreactors/gogo/v2/scripts/build-tinygo.sh)
- [README.md](/D:/Programing/go/chainreactors/gogo/v2/toolchain/tinygo/README.md)
- [manifest.env](/D:/Programing/go/chainreactors/gogo/v2/toolchain/tinygo/manifest.env)
- [regexp-syntax-repeat.patch](/D:/Programing/go/chainreactors/gogo/v2/toolchain/tinygo/regexp-syntax-repeat.patch)

改动目的：

- TinyGo 标准库的 `regexp/syntax` 对 counted repeat 的处理与标准 Go 不一致
- 这会直接影响 extractor/模板里的正则语义，尤其是重复次数相关表达式

处理方式：

- 不修改机器全局 `GOROOT`
- 构建时把 TinyGo host `GOROOT` 复制到 `v2/.toolchain/`
- 仅对缓存副本打补丁
- 构建完成后继续复用缓存

当前补丁内容：

- 为 `regexp/syntax/compile.go` 增加 `OpRepeat`
- 调整 `simplify.go`，避免过早把 counted repeat 展开掉

效果：

- 默认 TinyGo 构建现在保留 extractor 正则语义
- 避免为了规避 TinyGo 正则问题而整体关闭 extractor

### 3.3 TinyGo 下的 raw HTTP 响应解析

涉及文件：

- [response_parse.go](/D:/Programing/go/chainreactors/gogo/v2/pkg/response_parse.go)
- [response_parse_tinygo.go](/D:/Programing/go/chainreactors/gogo/v2/pkg/response_parse_tinygo.go)

改动目的：

- 标准 Go 版本直接使用 `parsers.NewResponseWithRaw`
- TinyGo 下原始 HTTP 响应解析链路更容易在某些路径上出现不稳定行为

处理方式：

- 标准 Go 保持原逻辑
- TinyGo 走轻量手工解析，只提取主扫描链路必需字段：
  - status
  - server
  - title
  - content/raw

效果：

- 默认扫描链路稳定
- 输出字段满足核心识别与结果落盘需求

### 3.4 TinyGo 下的 HTTP transport 和代理装配

涉及文件：

- [http_tinygo.go](/D:/Programing/go/chainreactors/gogo/v2/pkg/http_tinygo.go)
- [proxy_dialer_tinygo.go](/D:/Programing/go/chainreactors/gogo/v2/core/proxy_dialer_tinygo.go)

改动目的：

- TinyGo 下不复用标准 Go 那套完整 `http.Transport` 行为
- 只保留扫描主链路需要的最小能力

当前策略：

- `gogo` 自身的 HTTP 客户端使用最小 transport
- 代理拨号器仍可注入到 `DefaultTransport.DialContext`

效果：

- 主扫描 HTTP 能力可用
- 代理拨号保留最基本注入能力

### 3.5 TinyGo 下恢复默认模板加载，并新增可选空模板模式

涉及文件：

- [load_common_tinygo.go](/D:/Programing/go/chainreactors/gogo/v2/pkg/load_common_tinygo.go)
- [load_neutron_tinygo.go](/D:/Programing/go/chainreactors/gogo/v2/pkg/load_neutron_tinygo.go)
- [load_common_empty_tinygo.go](/D:/Programing/go/chainreactors/gogo/v2/pkg/load_common_empty_tinygo.go)
- [load_neutron_empty_tinygo.go](/D:/Programing/go/chainreactors/gogo/v2/pkg/load_neutron_empty_tinygo.go)
- [templates_empty.go](/D:/Programing/go/chainreactors/gogo/v2/pkg/templates_empty.go)

改动目的：

- 默认 TinyGo 版本需要保留真实指纹、workflow、extractor、neutron 模板能力
- 同时需要一个可选的极限瘦身模式，用于测试体积极限或产出最小壳

当前策略：

- 默认 TinyGo: `tinygo && !emptytemplates`
  - 正常加载 fingers / FingerPrintHub / extractor / workflow / neutron
- 极限瘦身模式: `tinygo && emptytemplates`
  - 仅保留空引擎和空模板装载器

效果：

- 默认版本是“可用扫描器”
- `emptytemplates` 是“主动裁剪版”，不是默认行为

### 3.6 TinyGo 下保留 FingerPrintHub active path

涉及文件：

- [load_common_tinygo.go](/D:/Programing/go/chainreactors/gogo/v2/pkg/load_common_tinygo.go)
- [httpFingerScan_tinygo.go](/D:/Programing/go/chainreactors/gogo/v2/engine/httpFingerScan_tinygo.go)

改动目的：

- 早期排障阶段曾临时关闭 FingerPrintHub active matching
- 当前版本已恢复引擎加载和 active match 调用路径

当前状态：

- 代码路径已恢复
- TinyGo 下模板装载前会先进行模板净化
- 本轮没有对 FingerPrintHub active matching 单独做大规模回归，只保证其编译、装载和调用链存在

### 3.7 TinyGo 下的 TLS / signal 降级

涉及文件：

- [tls_domains_tinygo.go](/D:/Programing/go/chainreactors/gogo/v2/pkg/tls_domains_tinygo.go)
- [signal_hook_tinygo.go](/D:/Programing/go/chainreactors/gogo/v2/pkg/signal_hook_tinygo.go)

当前行为：

- `HasTLS(resp)` 在 TinyGo 下固定返回 `false`
- `peerDNSNames(resp)` 在 TinyGo 下返回 `nil`
- 文件同步 signal hook 在 TinyGo 下为空实现

原因：

- 这部分能力依赖的标准库行为和运行时细节在 TinyGo 下没有必要强行等价实现
- 当前优先级低于“可构建、可扫描、可输出”

## 4. 外部依赖仓库兼容性改动

### 4.1 fingers

涉及文件：

- [fingerprinthub.go](/D:/Programing/go/chainreactors/fingers/fingerprinthub/fingerprinthub.go)
- [sanitize_template.go](/D:/Programing/go/chainreactors/fingers/fingerprinthub/sanitize_template.go)
- [sanitize_template_tinygo.go](/D:/Programing/go/chainreactors/fingers/fingerprinthub/sanitize_template_tinygo.go)

改动目的：

- `FingerprintHub` 原始数据里存在 `(?x)` 这类扩展正则前缀
- 标准 Go 与 TinyGo 对这类模式的兼容边界不同

处理方式：

- 共享加载逻辑统一调用 `sanitizeTemplateForTinyGo`
- 非 TinyGo 编译时，stub 为空实现
- TinyGo 编译时，递归遍历模板数据，只去掉字符串前缀 `(?x)`

说明：

- 这不是运行时 fallback，而是 build tag 下的 target-specific normalization
- 这样可以保持共享加载逻辑不分叉，且不影响标准 Go 语义

### 4.2 neutron

涉及文件：

- [utils.go](/D:/Programing/go/chainreactors/neutron/common/utils.go)
- [list.go](/D:/Programing/go/chainreactors/neutron/common/publicsuffix/list.go)
- [table.go](/D:/Programing/go/chainreactors/neutron/common/publicsuffix/table.go)
- [client_tinygo.go](/D:/Programing/go/chainreactors/neutron/protocols/http/client_tinygo.go)
- [go.mod](/D:/Programing/go/chainreactors/neutron/go.mod)
- [go.sum](/D:/Programing/go/chainreactors/neutron/go.sum)

改动目的：

- `publicsuffix-go` / `cookiejar` 链路不适合当前 TinyGo 目标
- 需要一个更可控、更小的 TinyGo HTTP 执行路径

处理方式：

- 去掉外部 `publicsuffix-go`
- 改为仓库内 `common/publicsuffix`
- TinyGo 下使用最小 HTTP client，不再尝试复刻标准 Go 的完整 cookie jar / redirect 管理

效果：

- `neutron` 模板执行链已恢复并完成实际验证
- 但 TinyGo 下的 HTTP client 语义不是标准 Go 等价实现

### 4.3 templates 子模块

涉及文件：

- [nacos.yaml](/D:/Programing/go/chainreactors/gogo/v2/templates/fingers/http/cloud/nacos.yaml)

改动目的：

- 增强 Nacos 指纹识别，方便 `-e auto` 命中相关 neutron 模板

说明：

- 这项改动更偏数据层增强，不是 TinyGo runtime 修复
- 但它直接参与了 TinyGo 版本的真实回归验证

## 5. 当前保留的功能

默认 TinyGo 构建当前保留：

- CLI 启动与参数解析
- 主机网络初始化
- 端口扫描和默认扫描链路
- HTTP 基础识别
- 被动指纹识别
- Fingers active HTTP match
- Neutron 模板加载与执行
- Extractor 加载与编译
- JSONLines 结果输出
- Workflow / port preset / extract preset 的正常装载

已做过真实验证的链路：

- 普通指纹扫描
- `-e auto` neutron 扫描
- `-E 模板名` 强制 neutron 扫描

## 6. 当前已放弃或显式降级的功能

这里的“放弃”分两类：

- 默认 TinyGo 构建中被显式降级
- 仅在 `emptytemplates` 极限瘦身模式下主动关闭

### 6.1 默认 TinyGo 构建中的降级项

#### A. TLS 证书域名提取

状态：

- 已放弃

表现：

- TinyGo 下不采集 TLS peer DNS names
- TinyGo 下不把响应视为具备标准 Go 等价的 TLS 元数据

原因：

- 这部分对标准库和 TLS 运行时细节依赖较强
- 对主扫描链路价值低于核心识别和执行稳定性

#### B. signal 驱动的文件同步行为

状态：

- 已放弃

表现：

- TinyGo 下 `installFileSyncSignalHandler` 为空实现

原因：

- 不影响扫描主流程
- 不值得为 TinyGo 单独保留复杂 signal 语义

#### C. neutron HTTP client 的完整 cookie / redirect 语义

状态：

- 部分放弃

表现：

- TinyGo 下未启用 `cookiejar`
- `FollowRedirects` / `MaxRedirects` / `CookieReuse` 这些配置结构仍存在，但当前最小 client 不保证与标准 Go 完全等价

影响：

- 依赖复杂 cookie 状态机或精细重定向控制的模板，可能与标准 Go 结果不一致

原因：

- 这是当前 TinyGo 版本里最典型的“可用优先”取舍
- 目标是保留可执行模板链，而不是复刻全部 HTTP 客户端细节

### 6.2 仅 `emptytemplates` 模式下主动放弃的功能

状态：

- 非默认行为
- 只在显式添加 `emptytemplates` build tag 时生效

被关闭的内容：

- embedded 指纹模板
- embedded neutron 模板
- embedded extractor
- embedded workflow
- 基于这些 embedded 数据的扫描能力

原因：

- 用于测试最小体积极限
- 用于生成最小可运行壳，而不是功能完整版本

说明：

- 这不是当前默认 TinyGo 构建的功能缺失
- 默认 TinyGo 版本不走这个模式

## 7. 之前放弃、现在已恢复的功能

以下项目曾在排障早期被临时关闭，但当前默认 TinyGo 构建已经恢复：

- neutron 模板加载
- neutron 执行链
- extractor 加载
- extractor 正则语义
- FingerPrintHub 引擎装载

恢复原因：

- `regexp/syntax` 通过 patched toolchain 修复了 counted repeat 语义
- `neutron` 通过最小 HTTP client 和 `publicsuffix` 内置化避开了不稳定依赖
- `fingers` 通过 TinyGo 专用模板净化，绕开了 `(?x)` 这类模式差异

## 8. 推荐维护原则

后续继续做 TinyGo 兼容时，建议遵守下面几条：

- 优先用 build tag 隔离 TinyGo 逻辑，不污染标准 Go 主路径
- 优先保留共享调用点，把差异压缩到最小 shim/stub
- 如果只是为了压缩体积而裁剪功能，优先放到 `emptytemplates` 这类显式模式里，不要影响默认构建
- 对无法等价复刻的运行时行为，文档里明确写“降级”而不是假装兼容
- patched toolchain 必须通过脚本自动化，不能依赖人工修改全局 `GOROOT`

## 9. 相关提交

本轮相关提交：

- `gogo`: `b76f19d` `Refine TinyGo compatibility and build tooling`
- `fingers`: `07f7880` `Add TinyGo template sanitizer for FingerprintHub`
- `neutron`: `dd59a0e` `Remove publicsuffix-go from TinyGo path`
- `templates`: `71f9a74` `Refine nacos detection and drop debug spray dict`
