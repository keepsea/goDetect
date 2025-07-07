//==============================================================================
// checks/persistence.go - 持久化机制相关的检查项
//==============================================================================

package checks

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/keepsea/goDetect/types"
	"github.com/keepsea/goDetect/utils"
)

// CronJobsCheck 检查 Cron 任务
type CronJobsCheck struct{}

func (c CronJobsCheck) Description() string { return "检查 Cron 定时任务" }
func (c CronJobsCheck) Execute() []types.CheckResult {
	cr := types.CheckResult{
		Category:    "⏰ 持久化机制",
		Description: c.Description(),
		Explanation: "作用: Cron是Linux下用于持久化后门、执行恶意任务最常见的方式。\n检查方法: 读取系统级和所有用户级的crontab文件，并使用正则表达式匹配高危命令模式（如 `curl|sh`, `base64`, `wget` 等）。\n判断依据: 任何包含下载并执行、反弹shell等模式的定时任务都应被视为高度可疑。",
		NeedsManual: true,
	}

	var contentBuilder strings.Builder
	// 收集系统级cron
	sysCron, err := utils.RunCommand("cat", "/etc/crontab")
	if err == nil {
		contentBuilder.WriteString("--- /etc/crontab 内容 ---\n" + sysCron + "\n\n")
	}

	// 收集 /etc/cron.d/
	files, err := os.ReadDir("/etc/cron.d")
	if err == nil {
		contentBuilder.WriteString("--- /etc/cron.d/ 目录内容 ---\n")
		for _, f := range files {
			filePath := "/etc/cron.d/" + f.Name()
			fileContent, err := os.ReadFile(filePath)
			if err == nil {
				contentBuilder.WriteString(fmt.Sprintf("--- 文件: %s ---\n%s\n", filePath, string(fileContent)))
			}
		}
		contentBuilder.WriteString("\n")
	}

	// 收集用户级cron
	passwdFile, err := os.Open("/etc/passwd")
	if err == nil {
		defer passwdFile.Close()
		scanner := bufio.NewScanner(passwdFile)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.Split(line, ":")
			if len(parts) > 0 {
				username := parts[0]
				userCron, err := utils.RunCommand("crontab", "-u", username, "-l")
				if err == nil && strings.TrimSpace(userCron) != "" {
					contentBuilder.WriteString(fmt.Sprintf("--- 用户 '%s' 的 Cron 任务 ---\n%s\n\n", username, userCron))
				}
			}
		}
	}

	// ** NEW **: 智能检测可疑任务
	suspiciousPatterns := []string{`curl.*\|.*sh`, `wget.*\|.*sh`, `base64`, `nc\s`, `ncat\s`, `/tmp/`}
	re := regexp.MustCompile(strings.Join(suspiciousPatterns, "|"))
	var suspiciousJobs []string

	scanner := bufio.NewScanner(strings.NewReader(contentBuilder.String()))
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(strings.TrimSpace(line), "#") && re.MatchString(line) {
			suspiciousJobs = append(suspiciousJobs, line)
		}
	}

	cr.Details = contentBuilder.String()
	if len(suspiciousJobs) > 0 {
		cr.Result = fmt.Sprintf("发现 %d 条可疑的定时任务", len(suspiciousJobs))
		cr.Details += "\n\n--- 检测到的可疑任务 ---\n" + strings.Join(suspiciousJobs, "\n")
		cr.IsSuspicious = true
	} else {
		cr.Result = "未自动发现可疑模式的定时任务"
		cr.IsSuspicious = false
	}

	return []types.CheckResult{cr}
}

// SystemdTimersCheck 检查 Systemd Timers
type SystemdTimersCheck struct{}

func (c SystemdTimersCheck) Description() string { return "检查 Systemd Timers" }
func (c SystemdTimersCheck) Execute() []types.CheckResult {
	cr := types.CheckResult{
		Category:    "⏰ 持久化机制",
		Description: c.Description(),
		Explanation: "作用: Systemd Timers是比Cron更现代、更灵活的定时任务机制，同样可能被用于持久化后门。\n检查方法: 执行 `systemctl list-timers --all` 命令列出所有激活和非激活的定时器。\n判断依据: 需要人工审计列表中的定时器，确认其执行的单元（Unit）是否为合法、预期的系统或应用任务。",
		NeedsManual: true,
	}
	out, err := utils.RunCommand("systemctl", "list-timers", "--all")
	if err != nil {
		cr.Result, cr.Details, cr.IsSuspicious = "检查失败或系统未使用 Systemd", "无法执行 'systemctl list-timers': "+err.Error(), true
	} else {
		cr.Result = "提取所有 Systemd Timers 供人工审计"
		cr.Details = "--- 'systemctl list-timers --all' 原始输出 ---\n" + out
		// 由于难以制定通用规则，默认标记为需要人工确认，但不一定是可疑
		cr.IsSuspicious = false
	}
	return []types.CheckResult{cr}
}
