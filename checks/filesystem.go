// ==============================================================================
// checks/filesystem.go - 文件系统相关的检查项
// ==============================================================================
package checks

import (
	"fmt"
	"strings"

	"github.com/keepsea/goDetect/types"
	"github.com/keepsea/goDetect/utils"
)

// SuidSgidFilesCheck 查找 SUID/SGID 文件
type SuidSgidFilesCheck struct{}

func (c SuidSgidFilesCheck) Description() string { return "查找 SUID/SGID 文件" }
func (c SuidSgidFilesCheck) Execute() []types.CheckResult {
	cr := types.CheckResult{
		Category:    "🗂️ 文件系统",
		Description: c.Description(),
		Explanation: "作用: SUID/SGID文件允许程序以文件所有者/组的权限运行，是黑客常用的提权手段。\n检查方法: 使用 `find` 命令在整个文件系统查找具有SUID(4000)或SGID(2000)权限位的文件，并特别关注那些存在于/tmp、/var/tmp、/dev/shm等高危目录中的此类文件。\n判断依据: 任何存在于临时目录或用户家目录下的SUID/SGID文件都应被视为极度可疑。",
		NeedsManual: true,
	}

	// ** MODIFIED **: 分两步检查，优先查找高危目录
	var suspiciousFiles []string
	highRiskDirs := []string{"/tmp", "/var/tmp", "/dev/shm"}

	// 查找高危目录中的SUID/SGID文件
	for _, dir := range highRiskDirs {
		out, err := utils.RunCommand("find", dir, "-type", "f", `(`, "-perm", "-4000", "-o", "-perm", "-2000", `)`, "-ls")
		if err == nil && strings.TrimSpace(out) != "" {
			suspiciousFiles = append(suspiciousFiles, out)
		}
	}

	// 获取全盘扫描结果用于审计
	fullScanOut, _ := utils.RunCommand("find", "/", "-type", "f", `(`, "-perm", "-4000", "-o", "-perm", "-2000", `)`, "-ls")
	cr.Details = "--- 全盘扫描结果 ---\n" + fullScanOut

	if len(suspiciousFiles) > 0 {
		cr.Result = fmt.Sprintf("在高危目录中发现 %d 处SUID/SGID文件", len(suspiciousFiles))
		cr.Details += "\n\n--- 高危目录中的可疑SUID/SGID文件 ---\n" + strings.Join(suspiciousFiles, "\n")
		cr.IsSuspicious = true
	} else {
		cr.Result = "未在高危目录中发现SUID/SGID文件，仍建议人工审计全盘结果"
		cr.IsSuspicious = false
	}

	return []types.CheckResult{cr}
}

// RecentlyModifiedFilesCheck 检查近期修改的文件
type RecentlyModifiedFilesCheck struct {
	Path string
	Days int
}

func (c RecentlyModifiedFilesCheck) Description() string {
	return fmt.Sprintf("检查 %s 目录下过去 %d 天内被修改的文件", c.Path, c.Days)
}
func (c RecentlyModifiedFilesCheck) Execute() []types.CheckResult {
	cr := types.CheckResult{
		Category:    "🗂️ 文件系统",
		Description: fmt.Sprintf("检查 %s 目录下过去 %d 天内被修改的文件", c.Path, c.Days),
		NeedsManual: true, IsSuspicious: true,
	}
	out, err := utils.RunCommand("find", c.Path, "-type", "f", "-mtime", fmt.Sprintf("-%d", c.Days), "-ls")
	if err != nil {
		cr.Result, cr.Details = "检查失败", fmt.Sprintf("无法在 %s 目录执行 'find': %s", c.Path, err.Error())
	} else {
		cr.Result = fmt.Sprintf("提取 %s 目录下过去 %d 天内被修改的文件列表", c.Path, c.Days)
		cr.Details = "检查系统关键目录中近期被修改的文件有助于发现未授权的配置更改。\n\n--- 原始结果 ---\n" + out
	}
	return []types.CheckResult{cr}
}

// TempDirsCheck 检查临时目录
type TempDirsCheck struct{}

func (c TempDirsCheck) Description() string { return "检查临时目录中的可执行文件" }
func (c TempDirsCheck) Execute() []types.CheckResult {
	cr := types.CheckResult{
		Category:    "🗂️ 文件系统",
		Description: c.Description(),
		Explanation: "作用: 临时目录通常不应包含可执行文件。攻击者常将恶意脚本或程序放在此处执行。\n检查方法: 使用 `find` 命令查找 /tmp 和 /var/tmp 目录下具有执行权限的文件。\n判断依据: 任何在临时目录中找到的可执行文件都应被视为可疑。",
		NeedsManual: true,
	}

	// ** MODIFIED **: 精准查找可执行文件
	out, err := utils.RunCommand("find", "/tmp", "/var/tmp", "-type", "f", "-perm", "/a=x", "-ls")
	if err != nil {
		cr.Result, cr.Details, cr.IsSuspicious = "检查失败", "无法执行 'find' 命令: "+err.Error(), true
		return []types.CheckResult{cr}
	}

	fullListing, _ := utils.RunCommand("ls", "-la", "/tmp", "/var/tmp")
	cr.Details = "--- 临时目录完整列表 ---\n" + fullListing

	if strings.TrimSpace(out) != "" {
		cr.Result = "在临时目录中发现可执行文件"
		cr.Details += "\n\n--- 发现的可执行文件 ---\n" + out
		cr.IsSuspicious = true
	} else {
		cr.Result = "未在临时目录中发现可执行文件"
		cr.IsSuspicious = false
	}

	return []types.CheckResult{cr}
}
