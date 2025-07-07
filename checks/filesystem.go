package checks

import (
	"fmt"
	"strings"

	"github.com/keepsea/goDetect/rules"
	"github.com/keepsea/goDetect/types"
	"github.com/keepsea/goDetect/utils"
)

// --- SuidSgidFilesCheck ---
type SuidSgidFilesCheck struct {
	RuleEngine *rules.RuleEngine
	Dirs       []string
}

func (c SuidSgidFilesCheck) Description() string { return "查找 SUID/SGID 文件" }
func (c SuidSgidFilesCheck) Execute() []types.CheckResult {
	cr := types.CheckResult{
		Category: "🗂️ 文件系统", Description: c.Description(),
		Explanation: "作用: SUID/SGID文件允许程序以文件所有者/组的权限运行，是黑客常用的提权手段。\n检查方法: 使用 `find` 命令在指定目录（默认为'/'）查找具有SUID(4000)或SGID(2000)权限位的文件。\n判断依据: 规则引擎会根据 `rules/filesystem.yaml` 等文件中的规则进行判断。",
	}

	var allOutput []string
	for _, dir := range c.Dirs {
		out, err := utils.RunCommand("find", dir, "-type", "f", `(`, "-perm", "-4000", "-o", "-perm", "-2000", `)`, "-ls")
		if err == nil && strings.TrimSpace(out) != "" {
			allOutput = append(allOutput, fmt.Sprintf("--- 在目录 '%s' 中的扫描结果 ---\n%s", dir, out))
		}
	}

	if len(allOutput) == 0 {
		cr.IsSuspicious, cr.Result, cr.Details = false, "在指定目录中未发现SUID/SGID文件", "扫描目录: "+strings.Join(c.Dirs, ", ")
		return []types.CheckResult{cr}
	}

	cr.Details = strings.Join(allOutput, "\n\n")
	findings := c.RuleEngine.Match("SuidSgidFilesCheck", cr.Details)
	cr.Findings = findings

	if len(findings) > 0 {
		cr.IsSuspicious, cr.Result = true, fmt.Sprintf("发现 %d 个可疑的SUID/SGID文件", len(findings))
	} else {
		cr.IsSuspicious, cr.Result = false, "未发现可疑的SUID/SGID文件"
	}
	return []types.CheckResult{cr}
}

// --- RecentlyModifiedFilesCheck ---
type RecentlyModifiedFilesCheck struct {
	RuleEngine *rules.RuleEngine
	Path       string
	Days       int
}

func (c RecentlyModifiedFilesCheck) Description() string {
	return fmt.Sprintf("检查 %s 目录下过去%d天的修改", c.Path, c.Days)
}
func (c RecentlyModifiedFilesCheck) Execute() []types.CheckResult {
	cr := types.CheckResult{
		Category: "🗂️ 文件系统", Description: c.Description(),
		Explanation: "作用: 检查系统关键目录中近期被修改的文件，有助于发现未经授权的配置更改。\n检查方法: 执行 `find [PATH] -type f -mtime -[DAYS]` 命令。\n判断依据: 需要人工审计列表，确认所有文件的变动是否符合预期。",
	}
	out, err := utils.RunCommand("find", c.Path, "-type", "f", "-mtime", fmt.Sprintf("-%d", c.Days), "-ls")
	if err != nil {
		cr.IsSuspicious, cr.Result, cr.Details = true, "检查失败", fmt.Sprintf("无法在 %s 目录执行 'find': %s", c.Path, err.Error())
	} else {
		cr.IsSuspicious, cr.Result, cr.Details = false, "提取文件列表供审计", "--- 原始输出 ---\n"+out
	}
	return []types.CheckResult{cr}
}

// --- TempDirsCheck ---
type TempDirsCheck struct {
	RuleEngine *rules.RuleEngine
}

func (c TempDirsCheck) Description() string { return "检查临时目录中的可执行文件" }
func (c TempDirsCheck) Execute() []types.CheckResult {
	cr := types.CheckResult{
		Category: "🗂️ 文件系统", Description: c.Description(),
		Explanation: "作用: 临时目录通常不应包含可执行文件。攻击者常将恶意脚本或程序放在此处执行。\n检查方法: 使用 `find` 命令查找 /tmp 和 /var/tmp 目录下具有执行权限的文件。\n判断依据: 任何在临时目录中找到的可执行文件都应被视为可疑。",
	}
	out, err := utils.RunCommand("find", "/tmp", "/var/tmp", "-type", "f", "-perm", "/a=x", "-ls")
	if err != nil {
		cr.IsSuspicious, cr.Result, cr.Details = true, "检查失败", "无法执行 'find' 命令: "+err.Error()
		return []types.CheckResult{cr}
	}
	fullListing, _ := utils.RunCommand("ls", "-la", "/tmp", "/var/tmp")
	cr.Details = "--- 临时目录完整列表 ---\n" + fullListing

	if strings.TrimSpace(out) != "" {
		cr.IsSuspicious, cr.Result = true, "在临时目录中发现可执行文件"
		cr.Details += "\n\n--- 发现的可执行文件 ---\n" + out
	} else {
		cr.IsSuspicious, cr.Result = false, "未在临时目录中发现可执行文件"
	}
	return []types.CheckResult{cr}
}
