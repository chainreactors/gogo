package sdk

import (
	"testing"

	"github.com/chainreactors/gogo/v2/pkg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSimpleScan 简单场景测试
func TestSimpleScan(t *testing.T) {
	sdk := NewGogoSDK(pkg.DefaultRunnerOption)
	err := sdk.Init()
	require.NoError(t, err, "SDK 初始化失败")

	// 单个目标扫描
	result := sdk.ScanOne("127.0.0.1", "80")
	assert.NotNil(t, result, "扫描结果不应为 nil")
	assert.Equal(t, "127.0.0.1", result.Ip, "IP 地址应该匹配")
	assert.Equal(t, "80", result.Port, "端口应该匹配")
	t.Logf("扫描结果: %s", result.FullOutput())
}

// TestLoadYamlResource 加载指定yaml的resource测试
func TestLoadYamlResource(t *testing.T) {
	t.Run("加载默认配置", func(t *testing.T) {
		sdk := NewGogoSDK(pkg.DefaultRunnerOption)
		err := sdk.Init()
		require.NoError(t, err, "加载配置文件失败")
		assert.NotNil(t, sdk.RunOpt, "RunnerOption 不应为 nil")
		t.Log("默认配置文件加载成功")
	})

	t.Run("加载自定义指纹文件", func(t *testing.T) {
		err := pkg.LoadPortConfig("")
		require.NoError(t, err, "加载端口配置失败")

		// 加载自定义指纹文件
		customFingerFiles := []string{"../test.yaml"}
		err = pkg.LoadFinger(customFingerFiles)
		require.NoError(t, err, "加载自定义指纹文件失败")

		pkg.LoadNeutron("")
		t.Log("自定义指纹文件加载成功")

		// 使用自定义指纹进行扫描测试
		sdk := NewGogoSDK(pkg.DefaultRunnerOption)
		result := sdk.ScanOne("127.0.0.1", "80")
		assert.NotNil(t, result, "扫描结果不应为 nil")
		t.Logf("使用自定义指纹扫描结果: %s", result.FullOutput())

		if len(result.Frameworks) > 0 {
			t.Logf("识别到的框架: %v", result.Frameworks)
		}
	})
}

// TestBatchScan 批量扫描测试
func TestBatchScan(t *testing.T) {
	sdk := NewGogoSDK(pkg.DefaultRunnerOption)
	sdk.SetThreads(100)
	err := sdk.Init()
	require.NoError(t, err, "SDK 初始化失败")

	t.Run("批量扫描", func(t *testing.T) {
		results, err := sdk.Scan("127.0.0.1", "80,443")
		assert.NoError(t, err, "批量扫描不应返回错误")
		// 结果可能为空（如果端口未开放），但不应该是 nil
		t.Logf("批量扫描到 %d 个结果", len(results))
		for _, result := range results {
			t.Logf("发现端口: %s", result.FullOutput())
		}
	})

	t.Run("流式批量扫描", func(t *testing.T) {
		resultCh, err := sdk.ScanStream("127.0.0.1", "80,443")
		assert.NoError(t, err, "流式扫描不应返回错误")
		assert.NotNil(t, resultCh, "结果 channel 不应为 nil")

		count := 0
		for result := range resultCh {
			count++
			assert.NotNil(t, result, "结果不应为 nil")
			t.Logf("收到结果 #%d: %s", count, result.FullOutput())
		}
		t.Logf("流式扫描完成，共收到 %d 个结果", count)
	})
}

// TestWorkflowScan 工作流扫描测试
func TestWorkflowScan(t *testing.T) {
	sdk := NewGogoSDK(pkg.DefaultRunnerOption)
	sdk.SetThreads(100)
	err := sdk.Init()
	require.NoError(t, err, "SDK 初始化失败")

	t.Run("基础工作流", func(t *testing.T) {
		workflow := &pkg.Workflow{
			Name:    "test-workflow",
			IP:      "127.0.0.1",
			Ports:   "80,443",
			Verbose: 0,
		}

		results, err := sdk.WorkflowScan(workflow)
		assert.NoError(t, err, "工作流扫描不应返回错误")
		assert.NotNil(t, results, "结果不应为 nil")
		t.Logf("工作流扫描到 %d 个结果", len(results))
		for _, result := range results {
			t.Logf("工作流结果: %s", result.FullOutput())
		}
	})

	t.Run("流式工作流扫描", func(t *testing.T) {
		workflow := &pkg.Workflow{
			Name:    "stream-workflow",
			IP:      "127.0.0.1",
			Ports:   "80,443",
			Verbose: 0,
		}

		resultCh, err := sdk.WorkflowScanStream(workflow)
		assert.NoError(t, err, "流式工作流扫描不应返回错误")
		assert.NotNil(t, resultCh, "结果 channel 不应为 nil")

		count := 0
		for result := range resultCh {
			count++
			assert.NotNil(t, result, "结果不应为 nil")
			t.Logf("收到工作流结果 #%d: %s", count, result.FullOutput())
		}
		t.Logf("流式工作流扫描完成，共收到 %d 个结果", count)
	})
}
