# GoGo SDK 使用指南

GoGo SDK 是基于 [chainreactors/gogo](https://github.com/chainreactors/gogo) 项目构建的网络扫描 SDK，提供了简洁易用的 Go 语言接口。

## 特性

- 🚀 **简单易用**: 只需几行代码即可开始扫描
- 🎯 **四种扫描方法**: BatchScan（批量扫描）、WorkflowScan（工作流扫描）、Scan（单个扫描）
- 📡 **流式 API**: 支持实时返回扫描结果的 channel
- 🔧 **直接调用底层**: 直接调用 `engine.Dispatch` 获得最佳性能
- 🔇 **静默运行**: SDK 内部不产生控制台输出，仅通过日志系统记录调试信息
- 📋 **统一返回类型**: 所有方法统一返回 `*parsers.GOGOResult`

## 快速开始

### 安装

```bash
go get github.com/chainreactors/gogo/v2
```

### 基本使用

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/chainreactors/gogo/v2/pkg"
    "github.com/chainreactors/gogo/v2/sdk"
)

func main() {
    // 创建 SDK 实例
    gogoSDK := sdk.NewGogoSDK(pkg.DefaultRunnerOption)
    
    // 初始化 SDK（加载配置文件）
    err := gogoSDK.Init()
    if err != nil {
        log.Fatal("SDK 初始化失败:", err)
    }
    
    // 批量端口扫描
    results, err := gogoSDK.BatchScan("192.168.1.0/24", "80,443,22")
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("发现 %d 个开放端口\n", len(results))
    for _, result := range results {
        fmt.Println(result.FullOutput())
    }
}
```

## API 参考

### GogoEngine

主要的 SDK 结构体，提供四种核心扫描功能。

#### 创建实例

```go
// 创建 SDK 实例（需要传入 RunnerOption）
gogoSDK := sdk.NewGogoSDK(pkg.DefaultRunnerOption)

// 设置线程数（可选，默认 1000）
gogoSDK.SetThreads(500)

// 重要：必须调用 Init() 方法初始化 SDK
err := gogoSDK.Init()
if err != nil {
    log.Fatal("SDK 初始化失败:", err)
}
```

#### 初始化方法

SDK 提供了 `Init()` 方法来加载必要的配置文件：

```go
func (sdk *GogoEngine) Init() error
```

**功能:**
- 加载端口配置文件
- 加载指纹识别规则
- 加载漏洞检测模板

**示例:**
```go
gogoSDK := sdk.NewGogoSDK(pkg.DefaultRunnerOption)
err := gogoSDK.Init()
if err != nil {
    return fmt.Errorf("SDK 初始化失败: %v", err)
}
```

### 扫描方法

#### 1. BatchScan - 批量端口扫描

批量端口扫描，支持 CIDR 网段扫描，通过 ants 协程池进行高效调度。

```go
func (sdk *GogoEngine) BatchScan(ip, ports string) ([]*parsers.GOGOResult, error)
func (sdk *GogoEngine) BatchScanStream(ip, ports string) (<-chan *parsers.GOGOResult, error)
```

**参数:**
- `ip`: 目标 CIDR 网段，如 "192.168.1.0/24"、"10.0.0.0/16"
- `ports`: 端口配置，如 "80,443,22" 或 "top100"

**特性:**
- ✅ 支持 CIDR 网段扫描（如 192.168.1.0/24）
- ✅ 使用 ants 协程池进行高效并发调度
- ✅ 自动解析网段中的所有 IP 地址
- ✅ 支持多个端口批量扫描

**返回:**
- 同步版本返回 `[]*parsers.GOGOResult` 结果切片
- 流式版本返回 `<-chan *parsers.GOGOResult` 实时结果 channel

**示例:**
```go
// 同步批量扫描整个网段
results, err := gogoSDK.BatchScan("192.168.1.0/24", "80,443,22")
if err != nil {
    log.Fatal(err)
}
fmt.Printf("网段扫描完成，发现 %d 个开放端口\n", len(results))

// 流式批量扫描
resultCh, err := gogoSDK.BatchScanStream("10.0.0.0/16", "top1000")
if err != nil {
    log.Fatal(err)
}
for result := range resultCh {
    fmt.Printf("发现端口: %s:%s\n", result.Ip, result.Port)
}
```

#### 2. Scan - 单个目标扫描

对单个 IP 和单个端口进行直接扫描，不使用协程池调度。

```go
func (sdk *GogoEngine) Scan(ip, port string) *parsers.GOGOResult
```

**参数:**
- `ip`: 单个目标 IP 地址（不支持 CIDR）
- `port`: 单个目标端口

**特性:**
- ❌ 不支持 CIDR 网段（仅支持单个 IP）
- ❌ 不使用协程池调度
- ✅ 直接调用底层扫描引擎
- ✅ 立即返回扫描结果
- ✅ 适用于快速单点检测

**返回:**
- 返回 `*parsers.GOGOResult` 单个扫描结果

**示例:**
```go
// 单个目标扫描
result := gogoSDK.Scan("192.168.1.1", "80")
if result.Status != "" && result.Status != "closed" {
    fmt.Printf("端口开放: %s:%s [%s]\n", result.Ip, result.Port, result.Protocol)
    fmt.Println(result.FullOutput())
} else {
    fmt.Printf("端口关闭: %s:%s\n", result.Ip, result.Port)
}

// 批量单点扫描（手动循环）
targets := []struct{ ip, port string }{
    {"192.168.1.1", "80"},
    {"192.168.1.1", "443"},
    {"192.168.1.2", "22"},
}

for _, target := range targets {
    result := gogoSDK.Scan(target.ip, target.port)
    if result.Status != "" && result.Status != "closed" {
        fmt.Printf("发现开放端口: %s:%s\n", result.Ip, result.Port)
    }
}
```

#### 3. WorkflowScan - 自定义工作流扫描

使用完全自定义的工作流配置进行扫描，支持复杂的扫描策略。

```go
func (sdk *GogoEngine) WorkflowScan(workflow *pkg.Workflow) ([]*parsers.GOGOResult, error)
func (sdk *GogoEngine) WorkflowScanStream(workflow *pkg.Workflow) (<-chan *parsers.GOGOResult, error)
```

**特性:**
- ✅ 支持 CIDR 网段扫描
- ✅ 使用 ants 协程池调度
- ✅ 支持复杂的扫描配置
- ✅ 支持指纹识别和漏洞检测

**Workflow 参数说明:**
- `Name`: 工作流名称（可选）
- `Description`: 工作流描述（可选）
- `IP`: 目标 CIDR 网段
- `Ports`: 端口配置
- `Exploit`: 漏洞利用模式（"none", "auto", 或具体漏洞名）
- `Verbose`: 详细级别（0-2）

**示例:**
```go
// 创建自定义工作流
workflow := &pkg.Workflow{
    Name:        "web-security-scan",
    Description: "Web 安全扫描",
    IP:          "192.168.1.0/24",
    Ports:       "80,443,8080,8443",
    Exploit:     "auto",
    Verbose:     2,
}

// 执行自定义工作流
results, err := gogoSDK.WorkflowScan(workflow)
if err != nil {
    log.Fatal(err)
}

// 流式工作流扫描
resultCh, err := gogoSDK.WorkflowScanStream(workflow)
if err != nil {
    log.Fatal(err)
}
for result := range resultCh {
    fmt.Println(result.FullOutput())
}
```

### 方法对比

| 方法 | 支持 CIDR | 协程池调度 | 适用场景 | 性能 |
|------|-----------|------------|----------|------|
| **BatchScan** | ✅ | ✅ | 网段端口扫描 | 高 |
| **Scan** | ❌ | ❌ | 单点快速检测 | 中 |
| **WorkflowScan** | ✅ | ✅ | 复杂扫描策略 | 高 |

### 使用场景建议

#### 使用 BatchScan 的场景：
- 扫描整个网段的常用端口
- 需要高并发批量扫描
- 简单的端口开放性检测

```go
// 扫描内网 C 段的 Web 端口
results, err := gogoSDK.BatchScan("192.168.1.0/24", "80,443,8080,8443")
```

#### 使用 Scan 的场景：
- 快速检测单个服务是否可用
- 验证特定 IP 端口的连通性
- 不需要并发的简单检测

```go
// 快速检测单个服务
result := gogoSDK.Scan("192.168.1.1", "80")
```

#### 使用 WorkflowScan 的场景：
- 需要指纹识别和漏洞检测
- 复杂的扫描策略配置
- 需要详细的扫描结果

```go
// 全面的安全扫描
workflow := &pkg.Workflow{
    Name:        "security-scan",
    Description: "安全扫描",
    IP:          "192.168.1.0/24",
    Ports:       "top1000",
    Verbose:     2,
    Exploit:     "auto",
}
results, err := gogoSDK.WorkflowScan(workflow)
```

### parsers.GOGOResult 结构体

扫描结果的数据结构，SDK 统一返回此类型。

```go
type GOGOResult struct {
    Ip         string              `json:"ip"`         // IP 地址
    Port       string              `json:"port"`       // 端口
    Protocol   string              `json:"protocol"`   // 协议类型
    Status     string              `json:"status"`     // 状态信息
    Uri        string              `json:"uri,omitempty"`        // URI 路径
    Host       string              `json:"host,omitempty"`       // 主机名
    Frameworks common.Frameworks   `json:"frameworks,omitempty"` // 识别的框架
    Vulns      common.Vulns        `json:"vulns,omitempty"`      // 发现的漏洞
    Extracteds map[string][]string `json:"extracted,omitempty"`  // 提取的信息
    Title      string              `json:"title,omitempty"`      // 页面标题
    Midware    string              `json:"midware,omitempty"`    // 中间件信息
}
```

#### 结果输出方法

`parsers.GOGOResult` 结构体提供了多种输出方法：

```go
// 完整输出（推荐使用）
fmt.Println(result.FullOutput())

// 彩色输出（适用于终端）
fmt.Println(result.ColorOutput())

// JSON 输出
fmt.Println(result.JsonOutput())

// CSV 输出
fmt.Println(result.CsvOutput())

// 获取目标标识
fmt.Println(result.GetTarget())

// 获取基础URL
fmt.Println(result.GetBaseURL())

// 获取完整URL
fmt.Println(result.GetURL())

// 获取指定字段值
fmt.Println(result.Get("ip"))      // 获取 IP
fmt.Println(result.Get("port"))    // 获取端口
fmt.Println(result.Get("status"))  // 获取状态
fmt.Println(result.Get("title"))   // 获取标题
```

## 使用示例

### 1. 基础批量扫描

```go
// 扫描常用端口
results, err := gogoSDK.BatchScan("192.168.1.0/24", "80,443,22,21,23")
if err != nil {
    log.Fatal(err)
}

for _, result := range results {
    fmt.Printf("开放端口: %s:%s [%s]\n", result.Ip, result.Port, result.Protocol)
}
```

### 2. 流式批量扫描

```go
// 初始化 SDK
gogoSDK := sdk.NewGogoSDK(pkg.DefaultRunnerOption)
err := gogoSDK.Init()
if err != nil {
    log.Fatal("SDK 初始化失败:", err)
}

// 实时获取扫描结果
resultCh, err := gogoSDK.BatchScanStream("10.0.0.0/16", "top1000")
if err != nil {
    log.Fatal(err)
}

fmt.Println("开始实时扫描...")
count := 0
for result := range resultCh {
    count++
    fmt.Printf("[%d] 发现端口: %s:%s [%s]\n", count, result.Ip, result.Port, result.Protocol)
}
fmt.Printf("扫描完成！总共发现 %d 个开放端口\n", count)
```

### 3. 单个目标扫描

```go
// 初始化 SDK
gogoSDK := sdk.NewGogoSDK(pkg.DefaultRunnerOption)
err := gogoSDK.Init()
if err != nil {
    log.Fatal("SDK 初始化失败:", err)
}

// 单个目标扫描
result := gogoSDK.Scan("192.168.1.1", "80")
if result.Status != "" && result.Status != "closed" {
    fmt.Printf("端口开放: %s:%s [%s]\n", result.Ip, result.Port, result.Protocol)
    fmt.Println(result.FullOutput())
} else {
    fmt.Printf("端口关闭: %s:%s\n", result.Ip, result.Port)
}
```

### 4. 工作流扫描

```go
// 初始化 SDK
gogoSDK := sdk.NewGogoSDK(pkg.DefaultRunnerOption)
err := gogoSDK.Init()
if err != nil {
    log.Fatal("SDK 初始化失败:", err)
}

// 创建自定义工作流
workflow := &pkg.Workflow{
    Name:        "comprehensive-scan",
    Description: "全面扫描",
    IP:          "192.168.1.0/24",
    Ports:       "top100",
    Exploit:     "auto",   // 启用自动漏洞检测
    Verbose:     2,        // 启用深度指纹识别
}

// 执行工作流扫描
results, err := gogoSDK.WorkflowScan(workflow)
if err != nil {
    log.Fatal(err)
}

// 使用 FullOutput() 显示详细结果
fmt.Printf("工作流扫描完成！发现 %d 个服务\n", len(results))
for _, result := range results {
    fmt.Println(result.FullOutput())
}
```

## 端口配置

支持多种端口配置方式：

- **具体端口**: `"80,443,22,21"`
- **端口范围**: `"8000-8100"`
- **预设端口**: `"top1"`, `"top10"`, `"top100"`, `"top1000"`
- **混合配置**: `"80,443,8000-8100,top100"`

## 详细级别 (Verbose)

- **0**: 基础扫描，只检测端口开放状态
- **1**: 启用指纹识别，识别服务和框架
- **2**: 启用深度扫描，包含详细的指纹识别和信息收集

## 漏洞利用模式 (Exploit)

- **"none"**: 不进行漏洞扫描
- **"auto"**: 自动选择合适的漏洞检测模块
- **具体漏洞名**: 如 `"ms17010"`, `"weblogic"` 等

## 线程池配置

SDK 支持自定义线程池大小，以优化扫描性能：

### 线程数建议

- **小网段 (< 1000 IP)**: 100-500 线程
- **中等网段 (1000-10000 IP)**: 500-2000 线程  
- **大网段 (> 10000 IP)**: 2000-5000 线程
- **Windows 系统**: 建议不超过 1000 线程

### 配置方式

```go
// 创建时设置线程数
gogoSDK := sdk.NewGogoSDK(pkg.DefaultRunnerOption)
gogoSDK.SetThreads(1000)
err := gogoSDK.Init()

// 针对不同场景的配置
gogoSDK := sdk.NewGogoSDK(pkg.DefaultRunnerOption)
switch scanType {
case "internal":
    gogoSDK.SetThreads(2000) // 内网扫描
case "external":
    gogoSDK.SetThreads(500)  // 外网扫描
case "stealth":
    gogoSDK.SetThreads(100)  // 隐蔽扫描
}
err := gogoSDK.Init()
```

## 命令行工具

SDK 提供了完整的命令行工具示例：

### 编译运行

```bash
cd cmd/example/sdk
go build -o gogo-cli sdk.go
```

### 基本用法

```bash
# 批量端口扫描
./gogo-cli -i 192.168.1.0/24 -p 80,443,22

# 流式扫描
./gogo-cli -i 172.16.0.0/24 -p top1000 -s

# 自定义线程数
./gogo-cli -i 192.168.1.0/24 -t 1000 -p top100
```

### 命令行参数

- `-i`: 目标 IP/CIDR（必需）
- `-p`: 端口配置（默认: top1）
- `-t`: 线程数（默认: 1000）
- `-s`: 启用流式输出
- `-h`: 显示帮助

## 注意事项

1. **初始化要求**: 使用 SDK 前必须调用 `Init()` 方法进行初始化
2. **方法区别**: 
   - `BatchScan`: 支持 CIDR 网段，使用协程池调度
   - `Scan`: 仅支持单个 IP 和端口，直接调用底层引擎
3. **权限要求**: 某些扫描功能可能需要管理员权限
4. **网络环境**: 确保网络连接正常，防火墙允许扫描
5. **目标合法性**: 仅对授权的目标进行扫描
6. **资源限制**: 大网段扫描会消耗较多系统资源
7. **Channel 缓冲**: 流式 API 使用缓冲 channel，如果处理速度过慢可能会丢失结果
8. **线程数配置**: 合理配置线程数以获得最佳性能
9. **静默运行**: SDK 内部不会产生控制台输出，所有调试信息通过日志系统记录
10. **结果输出**: 推荐使用 `result.FullOutput()` 方法获取完整的格式化结果

## 错误处理

```go
// 初始化错误处理
gogoSDK := sdk.NewGogoSDK(pkg.DefaultRunnerOption)
err := gogoSDK.Init()
if err != nil {
    log.Fatalf("SDK 初始化失败: %v", err)
}

// 批量扫描错误处理
results, err := gogoSDK.BatchScan("192.168.1.0/24", "80,443")
if err != nil {
    log.Printf("扫描失败: %v", err)
    return
}

// 检查是否有结果
if len(results) == 0 {
    log.Println("未发现任何开放端口")
    return
}

// 处理结果
for _, result := range results {
    // 使用 FullOutput() 显示完整结果
    fmt.Println(result.FullOutput())
}

// 单个扫描错误处理
result := gogoSDK.Scan("192.168.1.1", "80")
if result.Status != "" && result.Status != "closed" {
    fmt.Println(result.FullOutput())
} else {
    fmt.Printf("端口关闭: %s:%s\n", result.Ip, result.Port)
}
```

## 完整示例

查看 `cmd/example/sdk/sdk.go` 文件获取完整的使用示例，包含批量扫描模式的演示。

## 许可证

本项目基于原 gogo 项目的许可证。