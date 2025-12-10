# GoGo SDK

GoGo SDK 提供了简洁的 Go API，用于端口扫描和服务指纹识别。

## 核心概念

SDK 由两部分组成：

1. **GogoEngine**: 管理持久化状态（指纹库、端口配置等）
2. **核心 API**:
   - `ScanStream`: 批量端口扫描（流式），返回 channel
   - `WorkflowStream`: 自定义工作流扫描（流式），返回 channel
   - `ScanOne`: 单目标快速扫描

其他 API（`Scan`、`Workflow`）都是对 Stream API 的简单封装，你也可以根据需要自行封装。

## 快速开始

```go
import "github.com/chainreactors/gogo/v2/sdk"

// 1. 创建 GogoEngine
engine := sdk.NewGogoEngine(nil)

// 2. 初始化（加载指纹库等）
engine.Init()

// 3. 使用
ctx := context.Background()

// 单目标扫描
result := engine.ScanOne(ctx, "127.0.0.1", "80")
fmt.Printf("%s [%s]\n", result.GetTarget(), result.Status)

// 批量端口扫描（流式）
resultCh, _ := engine.ScanStream(ctx, "192.168.1.0/24", "80,443,8080")
for result := range resultCh {
    fmt.Printf("%s:%s [%s] %s\n", result.Ip, result.Port, result.Status, result.Title)
}

// 工作流扫描
workflow := &pkg.Workflow{
    Name:    "web-scan",
    IP:      "example.com",
    Ports:   "top100",
    Verbose: 1,
}
resultCh, _ := engine.WorkflowStream(ctx, workflow)
for result := range resultCh {
    fmt.Printf("%s - %v\n", result.GetTarget(), result.Frameworks)
}
```

## 配置

### 使用默认配置

```go
engine := sdk.NewGogoEngine(nil)
```

默认配置包含：基础扫描、无漏洞检测、2秒超时、1000 线程。

### 自定义配置

```go
opt := &pkg.RunnerOption{
    VersionLevel: 2,       // 深度指纹识别（0-2）
    Exploit:      "auto",  // 启用漏洞检测
    Delay:        3,       // 超时时间（秒）
    Opsec:        true,    // 启用隐蔽模式
}

engine := sdk.NewGogoEngine(opt)
engine.SetThreads(500)  // 设置线程数
```

### 运行时修改

```go
engine.SetThreads(500)
```

## API 参考

### GogoEngine

```go
// 创建实例
engine := sdk.NewGogoEngine(opt)  // opt 为 nil 时使用默认配置

// 初始化（必须调用）
engine.Init()

// 设置参数
engine.SetThreads(threads)
```

### 核心 API

```go
// 单目标扫描
ScanOne(ctx, ip, port) -> *GOGOResult

// 批量扫描（流式）
ScanStream(ctx, ip, ports) -> channel

// 工作流扫描（流式）
WorkflowStream(ctx, workflow) -> channel
```

### 便捷 API

```go
// 批量扫描（同步）
Scan(ctx, ip, ports) -> []*GOGOResult

// 工作流扫描（同步）
Workflow(ctx, workflow) -> []*GOGOResult
```

## 配置选项

### RunnerOption 配置

**扫描配置**
- `VersionLevel`: 指纹识别级别（0: 基础, 1: 标准, 2: 深度）
- `Exploit`: 漏洞检测模式（"none", "auto", "ms17010", "smbghost" 等）
- `Delay`: HTTP 超时时间（秒）
- `HttpsDelay`: HTTPS 超时时间（秒）
- `Opsec`: 启用隐蔽模式
- `Debug`: 调试模式

**过滤配置**
- `ScanFilters`: 结果过滤规则
- `ExcludeCIDRs`: 排除的 IP 段

### Workflow 配置

**基本配置**
- `Name`: 工作流名称
- `Description`: 工作流描述
- `IP`: 目标 IP 或 CIDR（如 "192.168.1.0/24"）
- `Ports`: 端口配置（如 "80,443" 或 "top100"）

**扫描配置**
- `Verbose`: 详细级别（同 VersionLevel，0-2）
- `Exploit`: 漏洞利用模式
- `Ping`: 启用 ICMP 存活检测
- `NoScan`: 仅检测存活，不扫描端口

**输出配置**
- `File`: 输出文件名
- `Path`: 输出路径

### 端口配置

支持多种端口配置方式：
- **具体端口**: `"80,443,8080"`
- **端口范围**: `"8000-8100"`
- **预设端口**: `"top1"`, `"top10"`, `"top100"`, `"top1000"`
- **混合配置**: `"80,443,8000-8100,top100"`
- **特殊端口**: `"icmp"`, `"ping"`, `"smb"`, `"snmp"` 等

## 结果结构

```go
type GOGOResult struct {
    Ip         string              // IP 地址
    Port       string              // 端口
    Protocol   string              // 协议类型（http, https, tcp 等）
    Status     string              // 状态信息
    Title      string              // 页面标题
    Host       string              // 主机名
    Frameworks common.Frameworks   // 识别的框架
    Vulns      common.Vulns        // 发现的漏洞
    Extracteds map[string][]string // 提取的信息
    Timing     int64               // 扫描耗时（毫秒）
}
```

**常用方法**：
```go
result.FullOutput()   // 完整格式化输出
result.ColorOutput()  // 彩色输出
result.JsonOutput()   // JSON 格式
result.GetTarget()    // 获取目标标识 "ip:port"
result.GetBaseURL()   // 获取基础 URL
result.GetURL()       // 获取完整 URL
```

## 完整示例

### 示例 1: 简单端口扫描

```go
package main

import (
    "context"
    "fmt"
    "github.com/chainreactors/gogo/v2/sdk"
)

func main() {
    engine := sdk.NewGogoEngine(nil)
    engine.Init()

    ctx := context.Background()
    results, _ := engine.Scan(ctx, "127.0.0.1", "80,443,22")

    for _, r := range results {
        fmt.Printf("[+] %s:%s [%s] %s\n", r.Ip, r.Port, r.Status, r.Title)
    }
}
```

### 示例 2: 网段扫描（流式）

```go
package main

import (
    "context"
    "fmt"
    "time"
    "github.com/chainreactors/gogo/v2/sdk"
)

func main() {
    engine := sdk.NewGogoEngine(nil)
    engine.SetThreads(1000)
    engine.Init()

    // 设置 5 分钟超时
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
    defer cancel()

    resultCh, _ := engine.ScanStream(ctx, "192.168.1.0/24", "top100")

    count := 0
    for result := range resultCh {
        count++
        fmt.Printf("[%d] %s:%s [%s] %s\n",
            count, result.Ip, result.Port, result.Status, result.Title)
    }
    fmt.Printf("Total: %d services found\n", count)
}
```

### 示例 3: 深度指纹识别

```go
package main

import (
    "context"
    "fmt"
    "github.com/chainreactors/gogo/v2/pkg"
    "github.com/chainreactors/gogo/v2/sdk"
)

func main() {
    // 深度扫描配置
    opt := &pkg.RunnerOption{
        VersionLevel: 2,       // 深度指纹识别
        Delay:        3,
        Exploit:      "none",
    }

    engine := sdk.NewGogoEngine(opt)
    engine.SetThreads(200)
    engine.Init()

    workflow := &pkg.Workflow{
        Name:    "deep-scan",
        IP:      "example.com",
        Ports:   "80,443,8080,8443",
        Verbose: 2,
    }

    ctx := context.Background()
    results, _ := engine.Workflow(ctx, workflow)

    for _, r := range results {
        fmt.Printf("\n[+] %s:%s\n", r.Ip, r.Port)
        fmt.Printf("    Title: %s\n", r.Title)
        fmt.Printf("    Protocol: %s\n", r.Protocol)

        if len(r.Frameworks) > 0 {
            fmt.Println("    Frameworks:")
            for name, frame := range r.Frameworks {
                fmt.Printf("      - %s: %s\n", name, frame.Version)
            }
        }
    }
}
```

### 示例 4: 漏洞检测

```go
package main

import (
    "context"
    "fmt"
    "github.com/chainreactors/gogo/v2/pkg"
    "github.com/chainreactors/gogo/v2/sdk"
)

func main() {
    opt := &pkg.RunnerOption{
        VersionLevel: 1,
        Exploit:      "auto",  // 自动漏洞检测
    }

    engine := sdk.NewGogoEngine(opt)
    engine.Init()

    workflow := &pkg.Workflow{
        Name:    "vuln-scan",
        IP:      "192.168.1.0/24",
        Ports:   "445,3389",  // SMB 和 RDP
        Exploit: "auto",
        Verbose: 1,
    }

    ctx := context.Background()
    resultCh, _ := engine.WorkflowStream(ctx, workflow)

    for result := range resultCh {
        if len(result.Vulns) > 0 {
            fmt.Printf("[!] %s:%s - Found vulnerabilities:\n", result.Ip, result.Port)
            for name, vuln := range result.Vulns {
                fmt.Printf("    - %s: %s\n", name, vuln.Description)
            }
        }
    }
}
```

### 示例 5: Context 取消

```go
package main

import (
    "context"
    "fmt"
    "os"
    "os/signal"
    "syscall"
    "github.com/chainreactors/gogo/v2/sdk"
)

func main() {
    engine := sdk.NewGogoEngine(nil)
    engine.Init()

    // 创建可取消的 context
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    // 监听中断信号
    sigCh := make(chan os.Signal, 1)
    signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

    go func() {
        <-sigCh
        fmt.Println("\n[!] Received interrupt signal, cancelling...")
        cancel()
    }()

    // 开始扫描
    resultCh, _ := engine.ScanStream(ctx, "10.0.0.0/8", "top1")

    count := 0
    for result := range resultCh {
        count++
        fmt.Printf("[%d] %s:%s\n", count, result.Ip, result.Port)
    }

    fmt.Printf("\nScan finished, found %d results\n", count)
}
```

### 示例 6: 多实例共享配置

```go
package main

import (
    "context"
    "github.com/chainreactors/gogo/v2/sdk"
)

func main() {
    // 第一个实例初始化指纹库
    engine1 := sdk.NewGogoEngine(nil)
    engine1.Init()

    // 第二个实例共享已加载的指纹库
    engine2 := sdk.NewGogoEngine(nil)
    engine2.SetThreads(500)
    // 不需要再次 Init

    ctx := context.Background()

    // 并发使用
    go engine1.Scan(ctx, "192.168.1.0/24", "80,443")
    go engine2.Scan(ctx, "192.168.2.0/24", "80,443")
}
```

## 高级用法

### 自定义过滤规则

```go
opt := &pkg.RunnerOption{
    ScanFilters: [][]string{
        {"status", "==", "closed"},     // 过滤关闭的端口
        {"title", "contains", "404"},   // 过滤 404 页面
    },
}

engine := sdk.NewGogoEngine(opt)
```

### 排除 IP 段

```go
import "github.com/chainreactors/utils"

opt := &pkg.RunnerOption{
    ExcludeCIDRs: utils.CIDRs{
        utils.ParseCIDR("192.168.1.100/32"),
        utils.ParseCIDR("192.168.1.200-210"),
    },
}

engine := sdk.NewGogoEngine(opt)
```

### 隐蔽扫描

```go
opt := &pkg.RunnerOption{
    Opsec:  true,  // 启用隐蔽模式
    Delay:  5,     // 增加超时时间
}

engine := sdk.NewGogoEngine(opt)
engine.SetThreads(50)  // 降低并发数
```

## 性能优化

### 线程数配置建议

| 场景 | 推荐线程数 | 说明 |
|------|-----------|------|
| 小网段 (< 256 IP) | 100-300 | 快速扫描 |
| 中等网段 (256-4096 IP) | 500-1000 | 平衡性能 |
| 大网段 (> 4096 IP) | 1000-2000 | 高性能 |
| 外网扫描 | 100-500 | 避免触发防护 |
| 隐蔽扫描 | 10-50 | 低速扫描 |

### 超时配置

```go
opt := &pkg.RunnerOption{
    Delay:      2,  // HTTP 超时（秒）
    HttpsDelay: 3,  // HTTPS 超时（秒）
}
```

### Context 超时

```go
// 为整个扫描任务设置超时
ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
defer cancel()

results, _ := engine.Scan(ctx, "192.168.1.0/24", "top1000")
```

## 注意事项

1. **必须初始化**: 创建 `GogoEngine` 后必须调用 `Init()` 加载指纹库
2. **Context 管理**: 所有 API 都需要传入 context，建议使用 `WithTimeout` 避免无限等待
3. **共享状态**: 多个 `GogoEngine` 实例共享已加载的指纹库
4. **自动清理**: Stream 模式会自动清理资源
5. **权限要求**: ICMP 扫描需要管理员权限
6. **合法性**: 仅对授权的目标进行扫描

## 与 Spray SDK 对比

| 特性 | GoGo SDK | Spray SDK |
|------|----------|-----------|
| **用途** | 端口扫描 + 服务识别 | Web 路径扫描 + 指纹识别 |
| **输入** | IP/CIDR + 端口 | URL + 字典 |
| **协议** | TCP/UDP/ICMP | HTTP/HTTPS |
| **底层 API** | `ScanStream` / `WorkflowStream` | `CheckStream` / `BruteStream` |
| **上层 API** | `Scan` / `Workflow` | `Check` / `Brute` |
| **单目标** | `ScanOne` | - |
| **配置** | `RunnerOption` / `Workflow` | `core.Option` |

**共同点**：
- ✅ Stream API 为底层，Sync API 为上层封装
- ✅ 所有 API 都支持 context
- ✅ 共享持久化状态（指纹库等）
- ✅ 统一的命名规范

## 许可证

MIT License
