// ==============================================================================
// checks/network.go - 网络连接相关的检查项
// ==============================================================================
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

func (c ListeningPortsCheck) Description() string { return "检查监听端口" }
func (c ListeningPortsCheck) Execute() []types.CheckResult {
	cr := types.CheckResult{
		Category: "🔌 网络连接", Description: c.Description(),
		Explanation: "作用: 发现系统中所有正在监听网络连接的服务，以排查未经授权的后门或服务。\n检查方法: 执行 `ss -lntup` 或 `netstat -lntup` 命令。\n判断依据: 规则引擎会根据 `rules/network.yaml` 等文件中的规则（如查找已知恶意软件端口）进行判断，同时需要人工审计未知端口。",
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

func (c EstablishedConnectionsCheck) Description() string { return "检查已建立的TCP连接" }
func (c EstablishedConnectionsCheck) Execute() []types.CheckResult {
	cr := types.CheckResult{
		Category: "🔌 网络连接", Description: c.Description(),
		Explanation: "作用: 发现本机与外部服务器之间所有已建立的连接，并通过IP黑名单排查C2通信。\n检查方法: 执行 `ss -ntp` 命令。\n判断依据: 任何与已知恶意IP建立的连接都应被视为高危事件。",
	}
	out, err := utils.RunCommand("ss", "-ntp")
	if err != nil {
		out, _ = utils.RunCommand("netstat", "-ntp")
	}
	cr.Details = "--- 原始输出 ---\n" + out

	// ** NEW **: 使用IOC进行IP匹配
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

func (c PromiscuousModeCheck) Description() string { return "检查网卡是否处于混杂模式" }
func (c PromiscuousModeCheck) Execute() []types.CheckResult {
	cr := types.CheckResult{
		Category: "🔌 网络连接", Description: c.Description(),
		Explanation: "作用: 混杂模式允许网卡捕获网段内所有流经的数据包，而不仅仅是发给本机的数据包。通常只有网络嗅探工具会开启此模式。\n检查方法: 执行 `ip link` 命令。\n判断依据: 任何处于 `PROMISC` 状态的网卡都应被视为可疑。",
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
