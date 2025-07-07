//==============================================================================
// checks/webshell.go - Webshell 相关的检查项
//==============================================================================

package checks

import (
	"fmt"
	"os"

	"github.com/keepsea/goDetect/types"
	"github.com/keepsea/goDetect/utils"
)

// WebshellCheck 通过调用河马工具进行 Webshell 检测
type WebshellCheck struct {
	WebPath string
}

func (c WebshellCheck) Execute() []types.CheckResult {
	cr := types.CheckResult{Category: "🌐 Web安全", Description: "通过内部调用河马可执行程序 (hm) 进行 Webshell 检测", NeedsManual: true}
	scannerPath := "./hm"
	if _, err := os.Stat(scannerPath); os.IsNotExist(err) {
		cr.Result, cr.Details, cr.IsSuspicious = "扫描失败", "未在当前目录下找到河马工具 'hm'。", true
		return []types.CheckResult{cr}
	}
	out, err := utils.RunCommand(scannerPath, "scan", c.WebPath)
	if err != nil {
		cr.Result = "扫描脚本执行失败"
		cr.Details = fmt.Sprintf("执行 '%s scan %s' 时发生错误。\n\n--- 错误信息 ---\n%s", scannerPath, c.WebPath, err.Error())
		cr.IsSuspicious = true
	} else {
		cr.Result = "提取河马工具扫描结果供人工审计"
		cr.Details = "请仔细分析以下由河马工具生成的报告。\n\n--- 河马工具输出结果 ---\n" + out
		cr.IsSuspicious = true
	}
	return []types.CheckResult{cr}
}
