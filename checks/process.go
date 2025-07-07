// =============================================================================
// FILE: checks/process.go
// =============================================================================
package checks

import (
	"bufio"
	"fmt"
	"strings"

	"github.com/keepsea/goDetect/types"
	"github.com/keepsea/goDetect/utils"
)

// SuspiciousProcessesCheck 检查可疑进程
type SuspiciousProcessesCheck struct{}

func (c SuspiciousProcessesCheck) Execute() []types.CheckResult {
	cr := types.CheckResult{Category: "⚙️ 进程与服务", Description: "检查可疑进程 (例如从 /tmp 启动)"}
	out, err := utils.RunCommand("ps", "aux")
	if err != nil {
		cr.Result, cr.Details, cr.IsSuspicious = "检查失败", "无法执行 'ps aux' 命令: "+err.Error(), true
		return []types.CheckResult{cr}
	}
	var suspiciousProcs []string
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "/tmp/") || strings.Contains(line, "/var/tmp/") {
			suspiciousProcs = append(suspiciousProcs, line)
		}
	}
	if len(suspiciousProcs) > 0 {
		cr.Result = fmt.Sprintf("发现 %d 个从临时目录启动的进程", len(suspiciousProcs))
		cr.Details = "从 /tmp 或 /var/tmp 等临时目录启动的进程非常可疑。\n\n--- 原始结果 ---\n" + strings.Join(suspiciousProcs, "\n")
		cr.IsSuspicious, cr.NeedsManual = true, true
	} else {
		cr.Result, cr.IsSuspicious = "未发现从临时目录启动的进程", false
	}
	return []types.CheckResult{cr}
}

// DeletedRunningProcessesCheck 检查已删除但仍在运行的进程
type DeletedRunningProcessesCheck struct{}

func (c DeletedRunningProcessesCheck) Execute() []types.CheckResult {
	cr := types.CheckResult{Category: "⚙️ 进程与服务", Description: "检查已删除但仍在运行的进程 (lsof +L1)"}
	out, err := utils.RunCommand("lsof", "+L1")
	if err != nil {
		cr.Result, cr.Details, cr.IsSuspicious, cr.NeedsManual = "检查失败或无权限", "无法执行 'lsof +L1'，可能需要 root 权限: "+err.Error(), true, true
		return []types.CheckResult{cr}
	}
	lines := strings.Split(out, "\n")
	if len(lines) > 1 {
		out = strings.Join(lines[1:], "\n")
	}
	if strings.TrimSpace(out) != "" {
		cr.Result = "发现已删除但仍在内存中运行的进程"
		cr.Details = "这是一种常见的隐藏恶意软件的技术。\n\n--- 原始结果 ---\n" + out
		cr.IsSuspicious, cr.NeedsManual = true, true
	} else {
		cr.Result, cr.IsSuspicious = "未发现已删除但仍在运行的进程", false
	}
	return []types.CheckResult{cr}
}
