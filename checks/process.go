// =============================================================================
// FILE: checks/process.go
// =============================================================================
package checks

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/keepsea/goDetect/types"
	"github.com/keepsea/goDetect/utils"
)

// SuspiciousProcessesCheck 检查可疑进程
type SuspiciousProcessesCheck struct{}

func (c SuspiciousProcessesCheck) Description() string { return "检查从临时目录启动的进程" }
func (c SuspiciousProcessesCheck) Execute() []types.CheckResult {
	cr := types.CheckResult{
		Category:    "⚙️ 进程与服务",
		Description: c.Description(),
		Explanation: "作用: 攻击者常将恶意软件放置在/tmp或/var/tmp等临时目录中执行，以规避检测。此项检查旨在发现这类可疑行为。\n检查方法: 执行 `ps aux` 命令，并筛选出可执行文件路径包含 `/tmp/` 或 `/var/tmp/` 的进程。\n判断依据: 任何从临时目录启动的进程都应被视为可疑，需要人工确认其合法性。本工具会自动排除自身进程。",
	}

	out, err := utils.RunCommand("ps", "aux")
	if err != nil {
		cr.Result, cr.Details, cr.IsSuspicious = "检查失败", "无法执行 'ps aux' 命令: "+err.Error(), true
		return []types.CheckResult{cr}
	}

	// ** MODIFIED **: 排除自身进程
	myPid := os.Getpid()
	var suspiciousProcs []string
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		pid, err := strconv.Atoi(fields[1])
		if err != nil {
			continue
		}

		if (strings.Contains(line, "/tmp/") || strings.Contains(line, "/var/tmp/")) && pid != myPid {
			suspiciousProcs = append(suspiciousProcs, line)
		}
	}

	cr.Details = "--- 'ps aux' 原始输出 ---\n" + out

	if len(suspiciousProcs) > 0 {
		cr.Result = fmt.Sprintf("发现 %d 个从临时目录启动的可疑进程", len(suspiciousProcs))
		cr.Details += "\n\n--- 筛选出的可疑进程 ---\n" + strings.Join(suspiciousProcs, "\n")
		cr.IsSuspicious, cr.NeedsManual = true, true
	} else {
		cr.Result, cr.IsSuspicious = "正常", false
	}

	return []types.CheckResult{cr}
}

// DeletedRunningProcessesCheck 检查已删除但仍在运行的进程
type DeletedRunningProcessesCheck struct{}

func (c DeletedRunningProcessesCheck) Description() string {
	return "检查已删除但仍在运行的进程 (lsof)"
}
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
