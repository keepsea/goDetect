//==============================================================================
// checks/persistence.go - 持久化机制相关的检查项
//==============================================================================

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

func (c CronJobsCheck) Description() string { return "检查 Cron 定时任务" }
func (c CronJobsCheck) Execute() []types.CheckResult {
	cr := types.CheckResult{
		Category: "⏰ 持久化机制", Description: c.Description(),
		Explanation: "作用: Cron是Linux下用于持久化后门、执行恶意任务最常见的方式。\n检查方法: 读取系统级和所有用户级的crontab文件。\n判断依据: 规则引擎会根据 `rules/cron.yaml` 等文件中的规则（如 `curl|sh`, `base64` 等）进行判断。",
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

func (c SystemdTimersCheck) Description() string { return "检查 Systemd Timers" }
func (c SystemdTimersCheck) Execute() []types.CheckResult {
	cr := types.CheckResult{
		Category: "⏰ 持久化机制", Description: c.Description(),
		Explanation: "作用: Systemd Timers是比Cron更现代、更灵活的定时任务机制，同样可能被用于持久化后门。\n检查方法: 执行 `systemctl list-timers --all` 命令。\n判断依据: 需要人工审计列表中的定时器，确认其执行的单元（Unit）是否为合法、预期的系统或应用任务。",
	}
	out, err := utils.RunCommand("systemctl", "list-timers", "--all")
	if err != nil {
		cr.IsSuspicious, cr.Result, cr.Details = true, "检查失败或系统未使用 Systemd", "无法执行 'systemctl list-timers': "+err.Error()
	} else {
		cr.IsSuspicious, cr.Result, cr.Details = false, "提取所有 Systemd Timers 供审计", "--- 原始输出 ---\n"+out
	}
	return []types.CheckResult{cr}
}
