package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/chainreactors/gogo/v2/pkg"
	"github.com/chainreactors/gogo/v2/sdk"
)

// 命令行参数
var (
	ip      = flag.String("i", "", "目标 IP/CIDR，如 192.168.1.0/24")
	ports   = flag.String("p", "top1", "端口配置，如 80,443,22 或 top100")
	threads = flag.Int("t", 1000, "线程数")
	stream  = flag.Bool("s", false, "启用流式输出")
	help    = flag.Bool("h", false, "显示帮助信息")
)

func main() {
	flag.Parse()

	if *help || *ip == "" {
		showHelp()
		return
	}

	fmt.Println("=== GoGo SDK 命令行工具 ===")

	// 创建 SDK 实例
	gogoSDK := sdk.NewGogoSDK(pkg.DefaultRunnerOption)
	gogoSDK.SetThreads(*threads)

	// 初始化 SDK
	err := gogoSDK.Init()
	if err != nil {
		log.Fatalf("SDK 初始化失败: %v", err)
	}

	fmt.Printf("目标: %s\n", *ip)
	fmt.Printf("端口: %s\n", *ports)
	fmt.Printf("线程数: %d\n", *threads)
	fmt.Printf("流式输出: %t\n", *stream)
	fmt.Println()

	// 使用批量扫描模式
	runBatchScan(gogoSDK)
}

func showHelp() {
	fmt.Println("GoGo SDK 命令行工具")
	fmt.Println()
	fmt.Println("用法:")
	fmt.Printf("  %s -i <目标> [选项]\n", os.Args[0])
	fmt.Println()
	fmt.Println("必需参数:")
	fmt.Println("  -i string    目标 IP/CIDR，如 192.168.1.0/24")
	fmt.Println()
	fmt.Println("可选参数:")
	fmt.Println("  -p string    端口配置 (默认: top100)")
	fmt.Println("               支持: 80,443,22 或 top100 或 8000-8100")
	fmt.Println("  -t int       线程数 (默认: 1000)")
	fmt.Println("  -s           启用流式输出 (实时显示结果)")
	fmt.Println("  -h           显示此帮助信息")
	fmt.Println()
	fmt.Println("示例:")
	fmt.Printf("  %s -i 192.168.1.0/24 -p 80,443,22\n", os.Args[0])
	fmt.Printf("  %s -i 10.0.0.0/24 -p top1000 -t 500\n", os.Args[0])
	fmt.Printf("  %s -i 192.168.1.0/24 -p top100 -s\n", os.Args[0])
}

func runBatchScan(gogoSDK *sdk.GogoEngine) {
	fmt.Println("--- 执行批量端口扫描 ---")

	if *stream {
		// 流式端口扫描
		resultCh, err := gogoSDK.BatchScanStream(*ip, *ports)
		if err != nil {
			log.Fatalf("流式端口扫描启动失败: %v", err)
		}

		fmt.Println("开始流式扫描，实时显示结果...")
		count := 0
		for result := range resultCh {
			count++
			fmt.Printf("[%d] 发现端口: %s:%s [%s]\n", count, result.Ip, result.Port, result.Protocol)
		}
		fmt.Printf("\n端口扫描完成！总共发现 %d 个开放端口\n", count)
	} else {
		// 同步端口扫描
		results, err := gogoSDK.BatchScan(*ip, *ports)
		if err != nil {
			log.Fatalf("端口扫描失败: %v", err)
		}

		fmt.Printf("端口扫描完成！发现 %d 个开放端口\n", len(results))
		for _, result := range results {
			fmt.Print(result.FullOutput())
		}
	}
}
