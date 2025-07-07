// ==============================================================================
// checks/account.go - 账号与权限相关的检查项
// ==============================================================================
package checks

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/keepsea/goDetect/types"
	"github.com/keepsea/goDetect/utils"
)

// RootAccountsCheck 检查具有 root 权限 (UID=0) 的账户
type RootAccountsCheck struct{}

func (c RootAccountsCheck) Execute() []types.CheckResult {
	cr := types.CheckResult{
		Category:    "👤 账号安全",
		Description: "检查具有 root 权限 (UID=0) 的账户",
		NeedsManual: true,
	}
	content, err := ioutil.ReadFile("/etc/passwd")
	if err != nil {
		cr.Result, cr.Details, cr.IsSuspicious = "检查失败", "无法读取 /etc/passwd 文件: "+err.Error(), true
		return []types.CheckResult{cr}
	}
	var rootUsers []string
	scanner := bufio.NewScanner(strings.NewReader(string(content)))
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), ":")
		if len(parts) > 3 && parts[2] == "0" {
			rootUsers = append(rootUsers, parts[0])
		}
	}
	cr.Result = fmt.Sprintf("发现 %d 个 UID 为 0 的账户", len(rootUsers))
	cr.Details = "除 'root' 外的其他 UID 为 0 的账户都极度可疑，请确认其合法性。\n\n--- 原始结果 ---\n" + strings.Join(rootUsers, "\n")
	cr.IsSuspicious = len(rootUsers) > 1
	return []types.CheckResult{cr}
}

// EmptyPasswordAccountsCheck 检查空密码账户
type EmptyPasswordAccountsCheck struct{}

func (c EmptyPasswordAccountsCheck) Execute() []types.CheckResult {
	cr := types.CheckResult{Category: "👤 账号安全", Description: "检查空密码账户"}
	out, err := utils.RunCommand("getent", "shadow")
	if err != nil {
		cr.Result, cr.Details, cr.IsSuspicious, cr.NeedsManual = "检查失败", "无法执行 'getent shadow' 命令: "+err.Error(), true, true
		return []types.CheckResult{cr}
	}
	var emptyPassUsers []string
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), ":")
		if len(parts) > 1 && (parts[1] == "" || parts[1] == "!" || parts[1] == "!!" || parts[1] == "*") {
			emptyPassUsers = append(emptyPassUsers, parts[0])
		}
	}
	if len(emptyPassUsers) > 0 {
		cr.Result = fmt.Sprintf("发现 %d 个空密码或被锁定的账户", len(emptyPassUsers))
		cr.Details = "空密码账户存在巨大安全风险。\n\n--- 原始结果 ---\n" + strings.Join(emptyPassUsers, "\n")
		cr.IsSuspicious, cr.NeedsManual = true, true
	} else {
		cr.Result, cr.IsSuspicious = "未发现空密码账户", false
	}
	return []types.CheckResult{cr}
}

// SudoersCheck 检查 Sudoers 文件
type SudoersCheck struct{}

func (c SudoersCheck) Execute() []types.CheckResult {
	cr := types.CheckResult{Category: "👤 账号安全", Description: "检查 /etc/sudoers 和 /etc/sudoers.d/", NeedsManual: true, IsSuspicious: true}
	sudoersContent, err := utils.RunCommand("cat", "/etc/sudoers")
	if err != nil {
		sudoersContent = "无法读取 /etc/sudoers: " + err.Error()
	}
	sudoersDFiles, err := utils.RunCommand("ls", "-l", "/etc/sudoers.d/")
	if err != nil {
		sudoersDFiles = "无法列出 /etc/sudoers.d/ 目录: " + err.Error()
	}
	cr.Result = "提取 sudoers 配置供人工审计"
	cr.Details = "请仔细审查以下配置，确认所有授权都是合法且最小化的，特别注意 'NOPASSWD' 配置。\n\n--- /etc/sudoers 内容 ---\n" + sudoersContent + "\n\n--- /etc/sudoers.d/ 目录内容 ---\n" + sudoersDFiles
	return []types.CheckResult{cr}
}

// LastLoginsCheck 检查最近登录记录
type LastLoginsCheck struct{}

func (c LastLoginsCheck) Execute() []types.CheckResult {
	cr := types.CheckResult{Category: "👤 账号安全", Description: "检查最近登录记录 (last -n 20)", NeedsManual: true, IsSuspicious: true}
	out, err := utils.RunCommand("last", "-n", "20", "-a")
	if err != nil {
		cr.Result, cr.Details = "检查失败", "无法执行 'last' 命令: "+err.Error()
	} else {
		cr.Result = "提取最近 20 条登录记录供人工审计"
		cr.Details = "请检查有无来自未知 IP 或在非工作时间的可疑登录活动。\n\n--- 原始结果 ---\n" + out
	}
	return []types.CheckResult{cr}
}

// FailedLoginsCheck 检查失败登录记录
type FailedLoginsCheck struct{}

func (c FailedLoginsCheck) Execute() []types.CheckResult {
	cr := types.CheckResult{Category: "👤 账号安全", Description: "检查失败登录记录 (lastb -n 20)", NeedsManual: true, IsSuspicious: true}
	out, err := utils.RunCommand("lastb", "-n", "20", "-a")
	if err != nil {
		cr.Result, cr.Details = "检查失败或无权限", "无法执行 'lastb' 命令，可能需要 root 权限: "+err.Error()
	} else {
		cr.Result = "提取最近 20 条失败登录记录供人工审计"
		cr.Details = "大量的失败登录尝试可能意味着暴力破解攻击。\n\n--- 原始结果 ---\n" + out
	}
	return []types.CheckResult{cr}
}
