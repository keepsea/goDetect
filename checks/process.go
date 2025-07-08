package checks

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/keepsea/goDetect/rules"
	"github.com/keepsea/goDetect/types"
	"github.com/keepsea/goDetect/utils"
)

// --- SuspiciousProcessesCheck ---
type SuspiciousProcessesCheck struct {
	RuleEngine *rules.RuleEngine
}

func (c SuspiciousProcessesCheck) Name() string { return "SuspiciousProcessesCheck" }
func (c SuspiciousProcessesCheck) Execute() []types.CheckResult {
	cr := types.CheckResult{
		Category: "⚙️ 进程与服务",
	}
	out, err := utils.RunCommand("ps", "aux")
	if err != nil {
		cr.IsSuspicious, cr.Result, cr.Details = true, "检查失败", "无法执行 'ps aux' 命令: "+err.Error()
		return []types.CheckResult{cr}
	}

	myPid := os.Getpid()
	var filteredLines []string
	lines := strings.Split(out, "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		pid, err := strconv.Atoi(fields[1])
		if err != nil {
			continue
		}
		if pid != myPid {
			filteredLines = append(filteredLines, line)
		}
	}
	cr.Details = strings.Join(filteredLines, "\n")
	findings := c.RuleEngine.Match("SuspiciousProcessesCheck", cr.Details)
	cr.Findings = findings

	if len(findings) > 0 {
		cr.IsSuspicious, cr.Result = true, fmt.Sprintf("发现 %d 个可疑进程", len(findings))
	} else {
		cr.IsSuspicious, cr.Result = false, "未发现可疑进程"
	}
	return []types.CheckResult{cr}
}

// --- DeletedRunningProcessesCheck ---
type DeletedRunningProcessesCheck struct {
	RuleEngine *rules.RuleEngine
}

func (c DeletedRunningProcessesCheck) Name() string {
	return "DeletedRunningProcessesCheck"
}
func (c DeletedRunningProcessesCheck) Execute() []types.CheckResult {
	cr := types.CheckResult{
		Category: "⚙️ 进程与服务",
	}
	out, err := utils.RunCommand("lsof", "+L1")
	if err != nil {
		cr.IsSuspicious, cr.Result, cr.Details = true, "检查失败或无权限", "无法执行 'lsof +L1': "+err.Error()
		return []types.CheckResult{cr}
	}
	cr.Details = "--- 'lsof +L1' 原始输出 ---\n" + out

	if strings.Contains(cr.Details, "(deleted)") {
		cr.IsSuspicious, cr.Result = true, "发现已删除但仍在运行的进程"
	} else {
		cr.IsSuspicious, cr.Result = false, "未发现已删除但仍在运行的进程"
	}
	return []types.CheckResult{cr}
}
