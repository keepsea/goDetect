package checks

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/keepsea/goDetect/rules"
	"github.com/keepsea/goDetect/types"
	"github.com/keepsea/goDetect/utils"
)

// --- CronJobsCheck ---
type CronJobsCheck struct {
	RuleEngine *rules.RuleEngine
}

func (c CronJobsCheck) Name() string { return "CronJobsCheck" }
func (c CronJobsCheck) Execute() []types.CheckResult {
	cr := types.CheckResult{
		Category: "⏰ 持久化机制",
	}
	var contentBuilder strings.Builder
	sysCron, _ := os.ReadFile("/etc/crontab")
	contentBuilder.WriteString("--- /etc/crontab ---\n" + string(sysCron) + "\n\n")
	files, _ := os.ReadDir("/etc/cron.d")
	for _, f := range files {
		content, _ := os.ReadFile("/etc/cron.d/" + f.Name())
		contentBuilder.WriteString(fmt.Sprintf("--- /etc/cron.d/%s ---\n%s\n\n", f.Name(), string(content)))
	}
	passwdFile, err := os.Open("/etc/passwd")
	if err == nil {
		defer passwdFile.Close()
		scanner := bufio.NewScanner(passwdFile)
		for scanner.Scan() {
			parts := strings.Split(scanner.Text(), ":")
			if len(parts) > 0 {
				username := parts[0]
				userCron, err := utils.RunCommand("crontab", "-u", username, "-l")
				if err == nil && strings.TrimSpace(userCron) != "" {
					contentBuilder.WriteString(fmt.Sprintf("--- 用户 '%s' 的 Cron ---\n%s\n\n", username, userCron))
				}
			}
		}
	}
	cr.Details = contentBuilder.String()
	findings := c.RuleEngine.Match("CronJobsCheck", cr.Details)
	cr.Findings = findings

	if len(findings) > 0 {
		cr.IsSuspicious, cr.Result = true, fmt.Sprintf("发现 %d 条可疑的定时任务", len(findings))
	} else {
		cr.IsSuspicious, cr.Result = false, "未发现可疑模式的定时任务"
	}
	return []types.CheckResult{cr}
}

// --- SystemdTimersCheck ---
type SystemdTimersCheck struct {
	RuleEngine *rules.RuleEngine
}

func (c SystemdTimersCheck) Name() string { return "SystemdTimersCheck" }
func (c SystemdTimersCheck) Execute() []types.CheckResult {
	cr := types.CheckResult{
		Category: "⏰ 持久化机制",
	}
	out, err := utils.RunCommand("systemctl", "list-timers", "--all")
	if err != nil {
		cr.IsSuspicious, cr.Result, cr.Details = true, "检查失败或系统未使用 Systemd", "无法执行 'systemctl list-timers': "+err.Error()
	} else {
		cr.IsSuspicious, cr.Result, cr.Details = false, "提取所有 Systemd Timers 供审计", "--- 原始输出 ---\n"+out
	}
	return []types.CheckResult{cr}
}
