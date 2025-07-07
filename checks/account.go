package checks

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"regexp"
	"strings"

	"github.com/keepsea/goDetect/rules"
	"github.com/keepsea/goDetect/types"
	"github.com/keepsea/goDetect/utils"
)

// --- RootAccountsCheck ---
type RootAccountsCheck struct {
	RuleEngine *rules.RuleEngine
}

func (c RootAccountsCheck) Description() string { return "检查具有 root 权限 (UID=0) 的账户" }
func (c RootAccountsCheck) Execute() []types.CheckResult {
	cr := types.CheckResult{
		Category:    "👤 账号安全",
		Description: c.Description(),
		Explanation: "作用: 检查系统中是否存在除root之外的UID为0的特权账户。非root的特权账户是常见的后门形式。\n检查方法: 读取 /etc/passwd 文件，查找第三个字段（UID）为0的行。\n判断依据: 正常情况下，只有root用户的UID为0。任何其他账户如果UID为0，都应被视为极度可疑。",
	}
	content, err := ioutil.ReadFile("/etc/passwd")
	if err != nil {
		cr.IsSuspicious, cr.Result, cr.Details = true, "检查失败", "无法读取 /etc/passwd 文件: "+err.Error()
		return []types.CheckResult{cr}
	}
	cr.Details = "--- /etc/passwd 内容 ---\n" + string(content)

	var rootUsers []string
	scanner := bufio.NewScanner(strings.NewReader(string(content)))
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), ":")
		if len(parts) > 3 && parts[2] == "0" {
			rootUsers = append(rootUsers, parts[0])
		}
	}
	if len(rootUsers) == 1 && rootUsers[0] == "root" {
		cr.IsSuspicious, cr.Result = false, "正常"
	} else {
		cr.IsSuspicious, cr.Result = true, fmt.Sprintf("发现 %d 个UID为0的账户", len(rootUsers))
	}
	return []types.CheckResult{cr}
}

// --- EmptyPasswordAccountsCheck ---
type EmptyPasswordAccountsCheck struct {
	RuleEngine *rules.RuleEngine
}

func (c EmptyPasswordAccountsCheck) Description() string { return "检查空密码账户" }
func (c EmptyPasswordAccountsCheck) Execute() []types.CheckResult {
	cr := types.CheckResult{
		Category: "👤 账号安全", Description: c.Description(),
		Explanation: "作用: 空密码账户允许任何人无需密码即可登录，存在巨大安全风险。\n检查方法: 执行 `getent shadow` 或读取 `/etc/shadow`，检查密码字段是否为空或为锁定状态符号。\n判断依据: 除少数特定系统账户外，任何可登录用户的密码字段都不应为空。",
	}
	out, err := utils.RunCommand("getent", "shadow")
	if err != nil {
		cr.IsSuspicious, cr.Result, cr.Details = true, "检查失败", "无法执行 'getent shadow' 命令: "+err.Error()
		return []types.CheckResult{cr}
	}
	cr.Details = "--- 'getent shadow' 原始输出 ---\n" + out

	var emptyPassUsers []string
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), ":")
		if len(parts) > 1 && (parts[1] == "" || parts[1] == "!" || parts[1] == "!!" || parts[1] == "*") {
			emptyPassUsers = append(emptyPassUsers, parts[0])
		}
	}

	if len(emptyPassUsers) > 0 {
		cr.IsSuspicious, cr.Result = true, fmt.Sprintf("发现 %d 个空密码或被锁定的账户", len(emptyPassUsers))
	} else {
		cr.IsSuspicious, cr.Result = false, "未发现空密码账户"
	}
	return []types.CheckResult{cr}
}

// --- SudoersCheck ---
type SudoersCheck struct {
	RuleEngine *rules.RuleEngine
}

func (c SudoersCheck) Description() string { return "检查 Sudoers 配置" }
func (c SudoersCheck) Execute() []types.CheckResult {
	cr := types.CheckResult{
		Category: "👤 账号安全", Description: c.Description(),
		Explanation: "作用: Sudoers文件定义了哪些用户可以以其他用户（通常是root）的身份执行命令。不当的配置，特别是 `NOPASSWD`，会带来严重的安全风险。\n检查方法: 读取 /etc/sudoers 文件及 /etc/sudoers.d/ 目录下的所有文件。\n判断依据: 规则引擎会根据 `rules/sudoers.yaml` 等文件中的规则（如查找NOPASSWD）进行判断。",
	}
	var contentBuilder strings.Builder
	sudoersContent, _ := ioutil.ReadFile("/etc/sudoers")
	contentBuilder.WriteString("--- /etc/sudoers 内容 ---\n" + string(sudoersContent) + "\n\n")
	files, _ := ioutil.ReadDir("/etc/sudoers.d/")
	for _, f := range files {
		filePath := "/etc/sudoers.d/" + f.Name()
		fileContent, _ := ioutil.ReadFile(filePath)
		contentBuilder.WriteString(fmt.Sprintf("--- 文件: %s ---\n%s\n", filePath, string(fileContent)))
	}
	cr.Details = contentBuilder.String()
	findings := c.RuleEngine.Match("SudoersCheck", cr.Details)
	cr.Findings = findings

	if len(findings) > 0 {
		cr.IsSuspicious, cr.Result = true, fmt.Sprintf("发现 %d 条可疑Sudoers配置", len(findings))
	} else {
		cr.IsSuspicious, cr.Result = false, "未发现高危Sudoers配置"
	}
	return []types.CheckResult{cr}
}

// --- LastLoginsCheck ---
type LastLoginsCheck struct {
	RuleEngine *rules.RuleEngine
	Limit      int
}

func (c LastLoginsCheck) Description() string {
	return fmt.Sprintf("检查最近%d条登录记录", c.Limit)
}
func (c LastLoginsCheck) Execute() []types.CheckResult {
	cr := types.CheckResult{
		Category: "👤 账号安全", Description: c.Description(),
		Explanation: "作用: 审计最近的成功登录记录，以发现未经授权的访问活动。\n检查方法: 执行 `last` 命令，并使用 `ioc.yaml` 中的IP黑名单进行比对。\n判断依据: 任何来自已知恶意IP的登录都应被视为高危事件。",
	}
	out, err := utils.RunCommand("last", "-n", fmt.Sprintf("%d", c.Limit), "-a")
	if err != nil {
		cr.IsSuspicious, cr.Result, cr.Details = true, "检查失败", "无法执行 'last' 命令: "+err.Error()
		return []types.CheckResult{cr}
	}
	cr.Details = "--- 'last' 原始输出 ---\n" + out

	re := regexp.MustCompile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`)
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		matches := re.FindStringSubmatch(line)
		if len(matches) > 1 {
			ip := matches[1]
			findings := c.RuleEngine.MatchIOC("ip", ip)
			cr.Findings = append(cr.Findings, findings...)
		}
	}

	if len(cr.Findings) > 0 {
		cr.IsSuspicious, cr.Result = true, fmt.Sprintf("发现 %d 个来自可疑IP的登录", len(cr.Findings))
	} else {
		cr.IsSuspicious, cr.Result = false, "未发现来自已知可疑IP的登录"
	}
	return []types.CheckResult{cr}
}

// --- FailedLoginsCheck ---
type FailedLoginsCheck struct {
	RuleEngine *rules.RuleEngine
}

func (c FailedLoginsCheck) Description() string { return "检查失败登录记录" }
func (c FailedLoginsCheck) Execute() []types.CheckResult {
	cr := types.CheckResult{
		Category: "👤 账号安全", Description: c.Description(),
		Explanation: "作用: 监控失败的登录尝试，有助于发现针对系统的暴力破解攻击。\n检查方法: 执行 `lastb` 命令获取登录失败日志。\n判断依据: 规则引擎会根据 `rules/failed_logins.yaml` 中的规则（如统计同一IP的失败次数）进行判断。",
	}
	out, err := utils.RunCommand("lastb")
	if err != nil {
		cr.IsSuspicious, cr.Result, cr.Details = true, "检查失败或无权限", "无法执行 'lastb' 命令: "+err.Error()
		return []types.CheckResult{cr}
	}
	cr.Details = "--- 'lastb' 原始输出 ---\n" + out
	findings := c.RuleEngine.Match("FailedLoginsCheck", cr.Details)
	cr.Findings = findings

	if len(findings) > 0 {
		cr.IsSuspicious, cr.Result = true, fmt.Sprintf("发现 %d 种暴力破解嫌疑", len(findings))
	} else {
		cr.IsSuspicious, cr.Result = false, "未发现明显的暴力破解行为"
	}
	return []types.CheckResult{cr}
}
