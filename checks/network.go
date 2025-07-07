// ==============================================================================
// checks/network.go - 网络连接相关的检查项
// ==============================================================================

package checks

import (
	"strings"

	"github.com/keepsea/goDetect/types"
	"github.com/keepsea/goDetect/utils"
)

// ListeningPortsCheck 检查监听端口
type ListeningPortsCheck struct{}

func (c ListeningPortsCheck) Execute() []types.CheckResult {
	cr := types.CheckResult{Category: "🔌 网络连接", Description: "检查监听端口 (ss -lntup)", NeedsManual: true, IsSuspicious: true}
	out, err := utils.RunCommand("ss", "-lntup")
	if err != nil {
		out, err = utils.RunCommand("netstat", "-lntup")
		if err != nil {
			cr.Result, cr.Details = "检查失败", "无法执行 'ss' 和 'netstat' 命令: "+err.Error()
			return []types.CheckResult{cr}
		}
	}
	cr.Result = "提取所有 TCP/UDP 监听端口供人工审计"
	cr.Details = "请检查有无未知服务或程序开启的监听端口，这可能是后门。\n\n--- 原始结果 ---\n" + out
	return []types.CheckResult{cr}
}

// ** NEW ** EstablishedConnectionsCheck 检查已建立的网络连接
type EstablishedConnectionsCheck struct{}

func (c EstablishedConnectionsCheck) Execute() []types.CheckResult {
	cr := types.CheckResult{Category: "🔌 网络连接", Description: "检查已建立的TCP连接 (ss -ntp)", NeedsManual: true, IsSuspicious: true}
	out, err := utils.RunCommand("ss", "-ntp")
	if err != nil {
		out, err = utils.RunCommand("netstat", "-ntp")
		if err != nil {
			cr.Result, cr.Details = "检查失败", "无法执行 'ss' 和 'netstat' 命令: "+err.Error()
			return []types.CheckResult{cr}
		}
	}
	cr.Result = "提取所有已建立的TCP连接供人工审计"
	cr.Details = "请检查有无可疑的外部IP地址连接，这可能是C2通信。\n\n--- 原始结果 ---\n" + out
	return []types.CheckResult{cr}
}

// PromiscuousModeCheck 检查网卡混杂模式
type PromiscuousModeCheck struct{}

func (c PromiscuousModeCheck) Execute() []types.CheckResult {
	cr := types.CheckResult{Category: "🔌 网络连接", Description: "检查网卡是否处于混杂模式"}
	out, err := utils.RunCommand("ip", "link")
	if err != nil {
		cr.Result, cr.Details, cr.IsSuspicious = "检查失败", "无法执行 'ip link' 命令: "+err.Error(), true
		return []types.CheckResult{cr}
	}
	if strings.Contains(strings.ToUpper(out), "PROMISC") {
		cr.Result = "发现有网卡处于混杂模式"
		cr.Details = "混杂模式意味着网卡正在监听网络中的所有数据包，可能是网络嗅探的迹象。\n\n--- 原始结果 ---\n" + out
		cr.IsSuspicious, cr.NeedsManual = true, true
	} else {
		cr.Result, cr.IsSuspicious = "未发现处于混杂模式的网卡", false
	}
	return []types.CheckResult{cr}
}
