// ==============================================================================
// checks/kernel.go - 内核与模块相关的检查项
// ==============================================================================
package checks

import (
	"fmt"

	"github.com/keepsea/goDetect/rules"
	"github.com/keepsea/goDetect/types"
	"github.com/keepsea/goDetect/utils"
)

// --- KernelModulesCheck ---
type KernelModulesCheck struct {
	RuleEngine *rules.RuleEngine
}

func (c KernelModulesCheck) Description() string { return "检查已加载的内核模块" }
func (c KernelModulesCheck) Execute() []types.CheckResult {
	cr := types.CheckResult{
		Category: "🧠 内核与模块", Description: c.Description(),
		Explanation: "作用: Rootkit 可能会通过加载恶意内核模块来隐藏自身，这是最高权限的持久化方式之一。\n检查方法: 执行 `lsmod` 命令列出所有已加载的模块。\n判断依据: 规则引擎会根据 `rules/kernel.yaml` 等文件中的规则（如匹配已知恶意模块名）进行判断。",
	}
	out, err := utils.RunCommand("lsmod")
	if err != nil {
		cr.IsSuspicious, cr.Result, cr.Details = true, "检查失败", "无法执行 'lsmod' 命令: "+err.Error()
		return []types.CheckResult{cr}
	}
	cr.Details = "--- 'lsmod' 原始输出 ---\n" + out
	findings := c.RuleEngine.Match("KernelModulesCheck", cr.Details)
	cr.Findings = findings

	if len(findings) > 0 {
		cr.IsSuspicious, cr.Result = true, fmt.Sprintf("发现 %d 个可疑的内核模块", len(findings))
	} else {
		cr.IsSuspicious, cr.Result = false, "未发现可疑的内核模块"
	}
	return []types.CheckResult{cr}
}
