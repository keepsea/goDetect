package checks

import (
	"bufio"
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

func (c SuidSgidFilesCheck) Name() string { return "SuidSgidFilesCheck" }
func (c SuidSgidFilesCheck) Execute() []types.CheckResult {
	cr := types.CheckResult{
		Category: "🗂️ 文件系统",
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
	Paths      []string // ** FIXED **: Changed from Path to Paths
	Days       int
}

func (c RecentlyModifiedFilesCheck) Name() string {
	return fmt.Sprintf("RecentlyModifiedFilesCheck", strings.Join(c.Paths, ","), c.Days)
}
func (c RecentlyModifiedFilesCheck) Execute() []types.CheckResult {
	cr := types.CheckResult{
		Category: "🗂️ 文件系统",
	}

	var allOutput []string
	for _, path := range c.Paths {
		out, err := utils.RunCommand("find", path, "-type", "f", "-mtime", fmt.Sprintf("-%d", c.Days), "-ls")
		if err == nil && strings.TrimSpace(out) != "" {
			allOutput = append(allOutput, fmt.Sprintf("--- 在路径 '%s' 中的扫描结果 ---\n%s", path, out))
		}
	}

	if len(allOutput) == 0 {
		cr.IsSuspicious, cr.Result, cr.Details = false, "在指定路径中未发现近期修改的文件", "扫描路径: "+strings.Join(c.Paths, ", ")
		return []types.CheckResult{cr}
	}

	cr.IsSuspicious, cr.Result, cr.Details = false, "提取文件列表供审计", strings.Join(allOutput, "\n\n")
	return []types.CheckResult{cr}
}

// --- TempDirsCheck ---
type TempDirsCheck struct {
	RuleEngine *rules.RuleEngine
	TempDirs   []string
}

func (c TempDirsCheck) Name() string { return "TempDirsCheck" }
func (c TempDirsCheck) Execute() []types.CheckResult {
	cr := types.CheckResult{
		Category: "🗂️ 文件系统",
	}
	findArgs := append([]string{}, c.TempDirs...)
	findArgs = append(findArgs, "-ls")
	out, err := utils.RunCommand("find", findArgs...)
	if err != nil {
		cr.IsSuspicious, cr.Result, cr.Details = true, "检查失败", "无法执行 'find' 命令: "+err.Error()
		return []types.CheckResult{cr}
	}
	cr.Details = "--- 临时目录文件列表 ---\n" + out

	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) > 0 {
			fileName := fields[len(fields)-1]
			findings := c.RuleEngine.MatchIOC("filename", fileName)
			cr.Findings = append(cr.Findings, findings...)
		}
	}

	if len(cr.Findings) > 0 {
		cr.IsSuspicious, cr.Result = true, fmt.Sprintf("在临时目录中发现 %d 个可疑文件", len(cr.Findings))
	} else {
		cr.IsSuspicious, cr.Result = false, "未在临时目录中发现已知可疑文件"
	}
	return []types.CheckResult{cr}
}
