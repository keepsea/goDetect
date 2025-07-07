// ==============================================================================
// checks/kernel.go - 内核与模块相关的检查项
// ==============================================================================
package checks

import (
	"github.com/keepsea/goDetect/types"
	"github.com/keepsea/goDetect/utils"
)

// KernelModulesCheck 检查内核模块
type KernelModulesCheck struct{}

func (c KernelModulesCheck) Description() string { return "检查已加载的内核模块 (lsmod)" }
func (c KernelModulesCheck) Execute() []types.CheckResult {
	cr := types.CheckResult{Category: "🧠 内核与模块", Description: "检查已加载的内核模块 (lsmod)", NeedsManual: true, IsSuspicious: true}
	out, err := utils.RunCommand("lsmod")
	if err != nil {
		cr.Result, cr.Details = "检查失败", "无法执行 'lsmod' 命令: "+err.Error()
	} else {
		cr.Result = "提取已加载的内核模块列表供人工审计"
		cr.Details = "Rootkit 可能会通过加载恶意内核模块来隐藏自身。\n\n--- 原始结果 ---\n" + out
	}
	return []types.CheckResult{cr}
}
