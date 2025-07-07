// ==============================================================================
// checks/account.go - 账号与权限相关的检查项
// ==============================================================================
package checks

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"regexp"
	"strings"

	"github.com/keepsea/goDetect/types"
	"github.com/keepsea/goDetect/utils"
)

// RootAccountsCheck 检查具有 root 权限 (UID=0) 的账户

type RootAccountsCheck struct{}

func (c RootAccountsCheck) Description() string { return "检查具有 root 权限 (UID=0) 的账户" }
func (c RootAccountsCheck) Execute() []types.CheckResult {
	cr := types.CheckResult{
		Category:    "👤 账号安全",
		Description: c.Description(),
		Explanation: "作用: 检查系统中是否存在除root之外的UID为0的特权账户。非root的特权账户是常见的后门形式。\n检查方法: 读取 /etc/passwd 文件，查找第三个字段（UID）为0的行。\n判断依据: 正常情况下，只有root用户的UID为0。任何其他账户如果UID为0，都应被视为极度可疑。",
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

	cr.Details = "--- 查找到的UID为0的账户列表 ---\n" + strings.Join(rootUsers, "\n")

	// ** MODIFIED **: 智能判断逻辑
	if len(rootUsers) == 1 && rootUsers[0] == "root" {
		cr.Result, cr.IsSuspicious = "正常", false
	} else if len(rootUsers) > 1 {
		cr.Result = fmt.Sprintf("发现 %d 个 UID 为 0 的账户，存在非root特权账户", len(rootUsers))
		cr.IsSuspicious, cr.NeedsManual = true, true
	} else { // len == 0 or only non-root user
		cr.Result = "异常，未找到root账户或仅找到非root的特权账户"
		cr.IsSuspicious, cr.NeedsManual = true, true
	}

	return []types.CheckResult{cr}
}

// EmptyPasswordAccountsCheck 检查空密码账户
type EmptyPasswordAccountsCheck struct{}

func (c EmptyPasswordAccountsCheck) Description() string { return "检查空密码账户" }
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

func (c SudoersCheck) Description() string { return "检查 Sudoers 配置" }
func (c SudoersCheck) Execute() []types.CheckResult {
	cr := types.CheckResult{
		Category:    "👤 账号安全",
		Description: c.Description(),
		Explanation: "作用: Sudoers文件定义了哪些用户可以以其他用户（通常是root）的身份执行命令。不当的配置，特别是 `NOPASSWD`，会带来严重的安全风险。\n检查方法: 读取 /etc/sudoers 文件及 /etc/sudoers.d/ 目录下的所有文件，并使用正则表达式查找包含 `NOPASSWD` 的行。\n判断依据: 任何 `NOPASSWD` 配置都应被视为高危，需要仔细审计其必要性。",
		NeedsManual: true, // Sudoers配置总是需要人工最终确认
	}

	var contentBuilder strings.Builder
	var nopasswdLines []string

	// 检查主文件
	sudoersContent, _ := ioutil.ReadFile("/etc/sudoers")
	contentBuilder.WriteString("--- /etc/sudoers 内容 ---\n" + string(sudoersContent) + "\n\n")

	// 检查 /etc/sudoers.d/ 目录
	files, _ := ioutil.ReadDir("/etc/sudoers.d/")
	contentBuilder.WriteString("--- /etc/sudoers.d/ 目录内容 ---\n")
	for _, f := range files {
		filePath := "/etc/sudoers.d/" + f.Name()
		fileContent, _ := ioutil.ReadFile(filePath)
		contentBuilder.WriteString(fmt.Sprintf("--- 文件: %s ---\n%s\n", filePath, string(fileContent)))
	}

	// ** NEW **: 智能检测 NOPASSWD
	re := regexp.MustCompile(`(?i)\bNOPASSWD\b`) // (?i) 表示不区分大小写
	scanner := bufio.NewScanner(strings.NewReader(contentBuilder.String()))
	for scanner.Scan() {
		line := scanner.Text()
		if re.MatchString(line) && !strings.HasPrefix(strings.TrimSpace(line), "#") {
			nopasswdLines = append(nopasswdLines, line)
		}
	}

	cr.Details = contentBuilder.String()
	if len(nopasswdLines) > 0 {
		cr.Result = fmt.Sprintf("发现 %d 条 NOPASSWD 高危配置", len(nopasswdLines))
		cr.Details += "\n\n--- 检测到的 NOPASSWD 行 ---\n" + strings.Join(nopasswdLines, "\n")
		cr.IsSuspicious = true
	} else {
		cr.Result = "未发现 NOPASSWD 配置"
		cr.IsSuspicious = false
	}

	return []types.CheckResult{cr}
}

// LastLoginsCheck 检查最近登录记录
type LastLoginsCheck struct{}

func (c LastLoginsCheck) Description() string { return "检查最近登录记录 (last -n 20)" }
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

func (c FailedLoginsCheck) Description() string { return "检查失败登录记录" }
func (c FailedLoginsCheck) Execute() []types.CheckResult {
	cr := types.CheckResult{
		Category:    "👤 账号安全",
		Description: c.Description(),
		Explanation: "作用: 监控失败的登录尝试，有助于发现针对系统的暴力破解攻击。\n检查方法: 执行 `lastb` 命令获取登录失败日志，并统计来自同一IP的失败次数。\n判断依据: 在短时间内，来自同一IP的大量失败登录（默认阈值 > 10次）被视为可疑的暴力破解行为。",
		NeedsManual: true,
	}
	out, err := utils.RunCommand("lastb") // 获取全部日志进行分析
	if err != nil {
		cr.Result, cr.Details, cr.IsSuspicious = "检查失败或无权限", "无法执行 'lastb' 命令，可能需要 root 权限: "+err.Error(), true
		return []types.CheckResult{cr}
	}

	cr.Details = "--- 'lastb' 原始输出 ---\n" + out

	// ** NEW **: 智能分析暴力破解
	ipCounts := make(map[string]int)
	re := regexp.MustCompile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`)
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		matches := re.FindStringSubmatch(scanner.Text())
		if len(matches) > 1 {
			ipCounts[matches[1]]++
		}
	}

	var bruteForceAlerts []string
	for ip, count := range ipCounts {
		if count > 10 { // 设置阈值
			bruteForceAlerts = append(bruteForceAlerts, fmt.Sprintf("IP: %s, 失败次数: %d", ip, count))
		}
	}

	if len(bruteForceAlerts) > 0 {
		cr.Result = fmt.Sprintf("发现 %d 个IP存在暴力破解嫌疑", len(bruteForceAlerts))
		cr.Details += "\n\n--- 暴力破解嫌疑IP列表 ---\n" + strings.Join(bruteForceAlerts, "\n")
		cr.IsSuspicious = true
	} else {
		cr.Result = "未发现明显的暴力破解行为"
		cr.IsSuspicious = false
	}

	return []types.CheckResult{cr}
}
