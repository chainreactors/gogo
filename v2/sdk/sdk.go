package sdk

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/chainreactors/gogo/v2/core"
	"github.com/chainreactors/gogo/v2/engine"
	"github.com/chainreactors/gogo/v2/pkg"
	"github.com/chainreactors/logs"
	"github.com/chainreactors/parsers"
	"github.com/panjf2000/ants/v2"
)

// GogoEngine GoGo 扫描器 SDK
type GogoEngine struct {
	Threads int // 线程池大小，默认为 0 表示使用系统默认值
	RunOpt  *pkg.RunnerOption
}

func (sdk *GogoEngine) Init() error {
	// 加载配置文件中的全局变量
	err := pkg.LoadPortConfig("")
	if err != nil {
		return fmt.Errorf("load port config failed, %v", err)
	}

	err = pkg.LoadFinger(nil)
	if err != nil {
		return fmt.Errorf("load finger config failed, %v", err)
	}

	pkg.LoadNeutron("")

	return nil
}

// NewGogoEngine 创建新的 GoGo SDK 实例
func NewGogoEngine(opt *pkg.RunnerOption) *GogoEngine {
	if opt == nil {
		opt = pkg.DefaultRunnerOption
	}
	return &GogoEngine{
		Threads: 1000,
		RunOpt:  opt,
	}
}

// SetThreads 设置线程池大小
func (sdk *GogoEngine) SetThreads(threads int) {
	sdk.Threads = threads
}

// ScanOne 单个目标扫描，返回单个结果
func (sdk *GogoEngine) ScanOne(ctx context.Context, ip, port string) *parsers.GOGOResult {
	result := pkg.NewResult(ip, port)

	// 检查 context 是否已取消
	select {
	case <-ctx.Done():
		return result.GOGOResult
	default:
	}

	engine.Dispatch(sdk.RunOpt, result)
	return result.GOGOResult
}

// ScanStream 批量端口扫描流式模式（底层API），返回实时结果 channel
func (sdk *GogoEngine) ScanStream(ctx context.Context, ip, ports string) (<-chan *parsers.GOGOResult, error) {
	workflow := &pkg.Workflow{
		Name:        "port-scan",
		Description: "端口扫描",
		IP:          ip,
		Ports:       ports,
		Exploit:     "none",
		Verbose:     0,
	}

	return sdk.workflowStream(ctx, workflow)
}

// Scan 批量端口扫描，返回结果切片（基于 ScanStream）
func (sdk *GogoEngine) Scan(ctx context.Context, ip, ports string) ([]*parsers.GOGOResult, error) {
	resultCh, err := sdk.ScanStream(ctx, ip, ports)
	if err != nil {
		return nil, err
	}

	var results []*parsers.GOGOResult
	for result := range resultCh {
		results = append(results, result)
	}

	return results, nil
}

// WorkflowStream 自定义工作流扫描流式模式（底层API），返回实时结果 channel
func (sdk *GogoEngine) WorkflowStream(ctx context.Context, workflow *pkg.Workflow) (<-chan *parsers.GOGOResult, error) {
	return sdk.workflowStream(ctx, workflow)
}

// Workflow 自定义工作流扫描，返回结果切片（基于 WorkflowStream）
func (sdk *GogoEngine) Workflow(ctx context.Context, workflow *pkg.Workflow) ([]*parsers.GOGOResult, error) {
	resultCh, err := sdk.WorkflowStream(ctx, workflow)
	if err != nil {
		return nil, err
	}

	var results []*parsers.GOGOResult
	for result := range resultCh {
		results = append(results, result)
	}

	return results, nil
}

// workflowStream 执行工作流的核心函数，返回结果 channel
func (sdk *GogoEngine) workflowStream(ctx context.Context, workflow *pkg.Workflow) (<-chan *parsers.GOGOResult, error) {
	logs.Log.Important("workflow " + workflow.Name + " starting")

	// 创建基础配置
	baseConfig := pkg.NewDefaultConfig(sdk.RunOpt)
	config := workflow.PrepareConfig(baseConfig)

	// 初始化配置
	preparedConfig, err := core.InitConfig(config)
	if err != nil {
		return nil, fmt.Errorf("配置初始化失败: %v", err)
	}

	// 如果 SDK 设置了线程数，使用 SDK 的设置
	if sdk.Threads > 0 {
		preparedConfig.Threads = sdk.Threads
	}

	// 创建结果 channel
	resultCh := make(chan *parsers.GOGOResult, 100)

	// 启动扫描 goroutine
	go func() {
		defer close(resultCh)
		defer config.Close()

		var wg sync.WaitGroup
		var aliveCount int32

		// 创建扫描池
		scanPool, _ := ants.NewPoolWithFunc(preparedConfig.Threads, func(i interface{}) {
			defer wg.Done()

			// 检查 context 是否已取消
			select {
			case <-ctx.Done():
				return
			default:
			}

			ipPort := i.([]string)
			result := pkg.NewResult(ipPort[0], ipPort[1])

			// 调用扫描引擎
			engine.Dispatch(preparedConfig.RunnerOpt, result)

			if result.Open {
				atomic.AddInt32(&aliveCount, 1)
				// 发送结果到 channel
				select {
				case resultCh <- result.GOGOResult:
				case <-ctx.Done():
					return
				default:
					logs.Log.Debugf("result channel full, dropping result for %s", result.GetTarget())
				}
			}
		})
		defer scanPool.Release()

		// 扫描目标
		for _, cidr := range preparedConfig.CIDRs {
			for ip := range cidr.Range() {
				// 检查 context 是否已取消
				select {
				case <-ctx.Done():
					logs.Log.Debug("workflow cancelled by context")
					wg.Wait()
					return
				default:
				}

				ipStr := ip.String()
				if ip.Ver == 6 {
					ipStr = "[" + ipStr + "]"
				}

				for _, port := range preparedConfig.PortList {
					wg.Add(1)
					_ = scanPool.Invoke([]string{ipStr, port})
				}
			}
		}

		wg.Wait()
		logs.Log.Debugf("workflow %s completed, found %d alive hosts", workflow.Name, aliveCount)
	}()

	return resultCh, nil
}
