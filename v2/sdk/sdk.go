package sdk

import (
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

type TargetConfig struct {
	IP   string
	Port string
}

func (tc *TargetConfig) NewResult() *pkg.Result {
	return pkg.NewResult(tc.IP, tc.Port)
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

// NewGogoSDK 创建新的 GoGo SDK 实例
func NewGogoSDK(opt *pkg.RunnerOption) *GogoEngine {
	return &GogoEngine{
		Threads: 1000, // 0 表示使用系统默认值
		RunOpt:  opt,
	}
}

// SetThreads 设置线程池大小
func (sdk *GogoEngine) SetThreads(threads int) {
	sdk.Threads = threads
}

// ScanOne 单个目标扫描，返回单个结果
func (sdk *GogoEngine) ScanOne(ip, port string) *parsers.GOGOResult {
	result := pkg.NewResult(ip, port)
	engine.Dispatch(sdk.RunOpt, result)
	return result.GOGOResult
}

// Scan 批量端口扫描，返回结果切片
func (sdk *GogoEngine) Scan(ip, ports string) ([]*parsers.GOGOResult, error) {
	workflow := &pkg.Workflow{
		Name:        "port-scan",
		Description: "端口扫描",
		IP:          ip,
		Ports:       ports,
		Exploit:     "none",
		Verbose:     0, // 基础扫描
	}

	return sdk.executeWorkflow(workflow)
}

// ScanStream 批量端口扫描流式模式，返回实时结果 channel
func (sdk *GogoEngine) ScanStream(ip, ports string) (<-chan *parsers.GOGOResult, error) {
	workflow := &pkg.Workflow{
		Name:        "port-scan",
		Description: "端口扫描",
		IP:          ip,
		Ports:       ports,
		Exploit:     "none",
		Verbose:     0, // 基础扫描
	}

	return sdk.executeWorkflowStream(workflow)
}

// WorkflowScan 自定义工作流扫描，返回结果切片
func (sdk *GogoEngine) WorkflowScan(workflow *pkg.Workflow) ([]*parsers.GOGOResult, error) {
	return sdk.executeWorkflow(workflow)
}

// WorkflowScanStream 自定义工作流扫描流式模式，返回实时结果 channel
func (sdk *GogoEngine) WorkflowScanStream(workflow *pkg.Workflow) (<-chan *parsers.GOGOResult, error) {
	return sdk.executeWorkflowStream(workflow)
}

// executeWorkflow 执行工作流，返回所有结果
func (sdk *GogoEngine) executeWorkflow(workflow *pkg.Workflow) ([]*parsers.GOGOResult, error) {
	resultCh, err := sdk.executeWorkflowStream(workflow)
	if err != nil {
		return nil, err
	}

	var results []*parsers.GOGOResult
	for result := range resultCh {
		results = append(results, result)
	}

	return results, nil
}

// executeWorkflowStream 执行工作流的核心函数，返回结果 channel
func (sdk *GogoEngine) executeWorkflowStream(workflow *pkg.Workflow) (<-chan *parsers.GOGOResult, error) {
	logs.Log.Important("workflow " + workflow.Name + " starting")

	// 创建基础配置
	baseConfig := pkg.NewDefaultConfig(pkg.DefaultRunnerOption)
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

			result := i.(*TargetConfig).NewResult()

			// 调用扫描引擎
			engine.Dispatch(preparedConfig.RunnerOpt, result)

			if result.Open {
				atomic.AddInt32(&aliveCount, 1)
				// 发送结果到 channel
				select {
				case resultCh <- result.GOGOResult:
				default:
					logs.Log.Debugf("result channel full, dropping result for %s", result.GetTarget())
				}
			}
		})
		defer scanPool.Release()

		// 扫描目标
		for _, cidr := range preparedConfig.CIDRs {
			for ip := range cidr.Range() {
				ipStr := ip.String()
				if ip.Ver == 6 {
					ipStr = "[" + ipStr + "]"
				}

				for _, port := range preparedConfig.PortList {
					target := &TargetConfig{
						IP:   ipStr,
						Port: port,
					}
					wg.Add(1)
					_ = scanPool.Invoke(target)
				}
			}
		}

		wg.Wait()
		logs.Log.Debugf("workflow %s completed, found %d alive hosts", workflow.Name, aliveCount)
	}()

	return resultCh, nil
}
