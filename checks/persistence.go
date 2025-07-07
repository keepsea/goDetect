//==============================================================================
// checks/persistence.go - 持久化机制相关的检查项
//==============================================================================

package checks

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/keepsea/goDetect/types"
	"github.com/keepsea/goDetect/utils"
)

// CronJobsCheck 检查 Cron 任务
type CronJobsCheck struct{}

func (c CronJobsCheck) Execute() []types.CheckResult {
	cr := types.CheckResult{Category: "⏰ 持久化机制", Description: "检查系统和用户的 Cron 任务", NeedsManual: true, IsSuspicious: true}
	var details strings.Builder
	sysCron, err := utils.RunCommand("cat", "/etc/crontab")
	if err != nil {
		details.WriteString("无法读取 /etc/crontab: " + err.Error() + "\n\n")
	} else {
		details.WriteString("--- /etc/crontab 内容 ---\n" + sysCron + "\n\n")
	}
	passwdFile, err := os.Open("/etc/passwd")
	if err != nil {
		details.WriteString("无法打开 /etc/passwd: " + err.Error() + "\n")
	} else {
		defer passwdFile.Close()
		scanner := bufio.NewScanner(passwdFile)
		for scanner.Scan() {
			username := strings.Split(scanner.Text(), ":")[0]
			userCron, err := utils.RunCommand("crontab", "-u", username, "-l")
			if err == nil && strings.TrimSpace(userCron) != "" {
				details.WriteString(fmt.Sprintf("用户 '%s' 的 Cron 任务:\n%s\n\n", username, userCron))
			}
		}
	}
	cr.Result = "提取所有 Cron 任务配置供人工审计"
	cr.Details = "请检查有无可疑的定时任务。\n\n" + details.String()
	return []types.CheckResult{cr}
}

// SystemdTimersCheck 检查 Systemd Timers
type SystemdTimersCheck struct{}

func (c SystemdTimersCheck) Execute() []types.CheckResult {
	cr := types.CheckResult{Category: "⏰ 持久化机制", Description: "检查 Systemd Timers", NeedsManual: true, IsSuspicious: true}
	out, err := utils.RunCommand("systemctl", "list-timers", "--all")
	if err != nil {
		cr.Result, cr.Details = "检查失败或系统未使用 Systemd", "无法执行 'systemctl list-timers': "+err.Error()
	} else {
		cr.Result = "提取所有 Systemd Timers 供人工审计"
		cr.Details = "Systemd Timers 是另一种实现持久化的方式。\n\n--- 原始结果 ---\n" + out
	}
	return []types.CheckResult{cr}
}
