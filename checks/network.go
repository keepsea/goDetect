package checks

import (
	"bufio"
	"fmt"
	"regexp"
	"strings"

	"github.com/keepsea/goDetect/rules"
	"github.com/keepsea/goDetect/types"
	"github.com/keepsea/goDetect/utils"
)

// --- ListeningPortsCheck ---
type ListeningPortsCheck struct {
	RuleEngine *rules.RuleEngine
}

func (c ListeningPortsCheck) Name() string { return "ListeningPortsCheck" }
func (c ListeningPortsCheck) Execute() []types.CheckResult {
	cr := types.CheckResult{
		Category: "🔌 网络连接",
	}
	out, err := utils.RunCommand("ss", "-lntup")
	if err != nil {
		out, err = utils.RunCommand("netstat", "-lntup")
		if err != nil {
			cr.IsSuspicious, cr.Result, cr.Details = true, "检查失败", "无法执行 'ss' 和 'netstat' 命令: "+err.Error()
			return []types.CheckResult{cr}
		}
	}
	cr.Details = "--- 原始输出 ---\n" + out
	findings := c.RuleEngine.Match("ListeningPortsCheck", cr.Details)
	cr.Findings = findings

	if len(findings) > 0 {
		cr.IsSuspicious, cr.Result = true, fmt.Sprintf("发现 %d 个可疑的监听端口", len(findings))
	} else {
		cr.IsSuspicious, cr.Result = false, "未发现可疑监听端口"
	}
	return []types.CheckResult{cr}
}

// --- EstablishedConnectionsCheck ---
type EstablishedConnectionsCheck struct {
	RuleEngine *rules.RuleEngine
}

func (c EstablishedConnectionsCheck) Name() string { return "EstablishedConnectionsCheck" }
func (c EstablishedConnectionsCheck) Execute() []types.CheckResult {
	cr := types.CheckResult{
		Category: "🔌 网络连接",
	}
	out, err := utils.RunCommand("ss", "-ntp")
	if err != nil {
		out, _ = utils.RunCommand("netstat", "-ntp")
	}
	cr.Details = "--- 原始输出 ---\n" + out

	// 使用IOC进行IP匹配
	re := regexp.MustCompile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d+`)
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
		cr.IsSuspicious, cr.Result = true, fmt.Sprintf("发现 %d 个与可疑IP建立的连接", len(cr.Findings))
	} else {
		cr.IsSuspicious, cr.Result = false, "未发现与已知可疑IP的连接"
	}
	return []types.CheckResult{cr}
}

// --- PromiscuousModeCheck ---
type PromiscuousModeCheck struct {
	RuleEngine *rules.RuleEngine
}

func (c PromiscuousModeCheck) Name() string { return "PromiscuousModeCheck" }
func (c PromiscuousModeCheck) Execute() []types.CheckResult {
	cr := types.CheckResult{
		Category: "🔌 网络连接",
	}
	out, err := utils.RunCommand("ip", "link")
	if err != nil {
		cr.IsSuspicious, cr.Result, cr.Details = true, "检查失败", "无法执行 'ip link' 命令: "+err.Error()
		return []types.CheckResult{cr}
	}
	cr.Details = "--- 'ip link' 原始输出 ---\n" + out
	if strings.Contains(strings.ToUpper(out), "PROMISC") {
		cr.IsSuspicious, cr.Result = true, "发现有网卡处于混杂模式"
	} else {
		cr.IsSuspicious, cr.Result = false, "未发现处于混杂模式的网卡"
	}
	return []types.CheckResult{cr}
}
