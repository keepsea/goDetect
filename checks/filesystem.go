// ==============================================================================
// checks/filesystem.go - 文件系统相关的检查项
// ==============================================================================
package checks

import (
	"fmt"

	"github.com/keepsea/goDetect/types"
	"github.com/keepsea/goDetect/utils"
)

// SuidSgidFilesCheck 查找 SUID/SGID 文件
type SuidSgidFilesCheck struct{}

func (c SuidSgidFilesCheck) Execute() []types.CheckResult {
	cr := types.CheckResult{Category: "🗂️ 文件系统", Description: "查找 SUID/SGID 文件", NeedsManual: true, IsSuspicious: true}
	out, err := utils.RunCommand("find", "/", "-type", "f", `(`, "-perm", "-4000", "-o", "-perm", "-2000", `)`, "-ls")
	if err != nil {
		cr.Result, cr.Details = "检查失败", "无法执行 'find' 命令: "+err.Error()
	} else {
		cr.Result = "提取所有 SUID/SGID 文件列表供人工审计"
		cr.Details = "攻击者可能会利用 SUID/SGID 文件进行提权。\n\n--- 原始结果 ---\n" + out
	}
	return []types.CheckResult{cr}
}

// RecentlyModifiedFilesCheck 检查近期修改的文件
type RecentlyModifiedFilesCheck struct {
	Path string
	Days int
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

func (c TempDirsCheck) Execute() []types.CheckResult {
	cr := types.CheckResult{Category: "🗂️ 文件系统", Description: "检查 /tmp 和 /var/tmp 目录内容", NeedsManual: true, IsSuspicious: true}
	tmpOut, err1 := utils.RunCommand("ls", "-la", "/tmp")
	varTmpOut, err2 := utils.RunCommand("ls", "-la", "/var/tmp")
	if err1 != nil {
		tmpOut = "无法列出 /tmp 目录: " + err1.Error()
	}
	if err2 != nil {
		varTmpOut = "无法列出 /var/tmp 目录: " + err2.Error()
	}
	cr.Result = "提取临时目录内容供人工审计"
	cr.Details = "攻击者常在临时目录中存放恶意文件。\n\n--- /tmp 目录内容 ---\n" + tmpOut + "\n\n--- /var/tmp 目录内容 ---\n" + varTmpOut
	return []types.CheckResult{cr}
}
