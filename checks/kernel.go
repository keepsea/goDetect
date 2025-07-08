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

func (c KernelModulesCheck) Name() string { return "KernelModulesCheck" }
func (c KernelModulesCheck) Execute() []types.CheckResult {
	cr := types.CheckResult{
		Category: "🧠 内核与模块",
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
