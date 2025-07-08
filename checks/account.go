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

func (c RootAccountsCheck) Name() string { return "RootAccountsCheck" }
func (c RootAccountsCheck) Execute() []types.CheckResult {
	cr := types.CheckResult{
		Category: "👤 账号安全",
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

func (c EmptyPasswordAccountsCheck) Name() string { return "EmptyPasswordAccountsCheck" }
func (c EmptyPasswordAccountsCheck) Execute() []types.CheckResult {
	cr := types.CheckResult{
		Category: "👤 账号安全",
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

func (c SudoersCheck) Name() string { return "SudoersCheck" }
func (c SudoersCheck) Execute() []types.CheckResult {
	cr := types.CheckResult{
		Category: "👤 账号安全",
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

func (c LastLoginsCheck) Name() string {
	return fmt.Sprintf("LastLoginsCheck", c.Limit)
}
func (c LastLoginsCheck) Execute() []types.CheckResult {
	cr := types.CheckResult{
		Category: "👤 账号安全",
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

func (c FailedLoginsCheck) Name() string { return "FailedLoginsCheck" }
func (c FailedLoginsCheck) Execute() []types.CheckResult {
	cr := types.CheckResult{
		Category: "👤 账号安全",
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
