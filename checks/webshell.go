//==============================================================================
// checks/webshell.go - Webshell 相关的检查项
//==============================================================================

package checks

import (
	"encoding/csv"
	"fmt"
	"os"
	"strings"

	"github.com/keepsea/goDetect/types"
	"github.com/keepsea/goDetect/utils"
)

// WebshellCheck 通过调用河马工具并解析其CSV结果进行 Webshell 检测
type WebshellCheck struct {
	WebPath string
}

func (c WebshellCheck) Description() string {
	return "通过解析河马工具CSV结果进行 Webshell 检测"
}
func (c WebshellCheck) Execute() []types.CheckResult {
	cr := types.CheckResult{
		Category:    "🌐 Web安全",
		Description: "通过解析河马工具CSV结果进行 Webshell 检测",
		NeedsManual: true, // 结果需要人工最终确认
	}
	scannerPath := "./hm"
	resultFilePath := "./result.csv"

	// 1. 检查 hm 可执行文件
	if _, err := os.Stat(scannerPath); os.IsNotExist(err) {
		cr.Result, cr.Details, cr.IsSuspicious = "扫描失败", "未在当前目录下找到河马工具 'hm'。", true
		return []types.CheckResult{cr}
	}

	// 2. 运行扫描命令
	// 运行前先删除可能存在的旧报告，避免混淆
	os.Remove(resultFilePath)
	_, err := utils.RunCommand(scannerPath, "scan", c.WebPath)
	if err != nil {
		cr.Result = "扫描命令执行失败"
		cr.Details = fmt.Sprintf("执行 '%s scan %s' 时发生错误。\n\n--- 错误信息 ---\n%s", scannerPath, c.WebPath, err.Error())
		cr.IsSuspicious = true
		return []types.CheckResult{cr}
	}

	// 3. 检查并解析 result.csv
	// 扫描完成后，确保清理csv文件
	defer os.Remove(resultFilePath)

	csvFile, err := os.Open(resultFilePath)
	if os.IsNotExist(err) {
		// 如果文件不存在，说明河马工具未发现任何风险项
		cr.Result = "扫描完成，未发现风险文件"
		cr.Details = "河马工具未生成 result.csv，通常意味着没有发现可疑文件。"
		cr.IsSuspicious = false
		cr.NeedsManual = false // 明确无风险，无需人工介入
		return []types.CheckResult{cr}
	}
	if err != nil {
		cr.Result = "无法打开结果文件"
		cr.Details = "扫描已执行，但无法打开 result.csv 文件进行解析: " + err.Error()
		cr.IsSuspicious = true
		return []types.CheckResult{cr}
	}
	defer csvFile.Close()

	reader := csv.NewReader(csvFile)
	records, err := reader.ReadAll()
	if err != nil {
		cr.Result = "无法解析结果文件"
		cr.Details = "无法解析 result.csv 文件: " + err.Error()
		cr.IsSuspicious = true
		return []types.CheckResult{cr}
	}

	if len(records) <= 1 { // 小于等于1行，说明只有表头或文件为空
		cr.Result = "扫描完成，未在结果中发现风险项"
		cr.Details = "result.csv 文件为空，未报告任何可疑文件。"
		cr.IsSuspicious = false
		cr.NeedsManual = false
		return []types.CheckResult{cr}
	}

	// 4. 格式化结果为Markdown表格
	var tableBuilder strings.Builder
	// 写入表头
	tableBuilder.WriteString("| " + strings.Join(records[0], " | ") + " |\n")
	// 写入表头分隔符
	tableBuilder.WriteString("|" + strings.Repeat(" --- |", len(records[0])) + "\n")
	// 写入数据行
	for _, row := range records[1:] {
		tableBuilder.WriteString("| " + strings.Join(row, " | ") + " |\n")
	}

	cr.Result = fmt.Sprintf("发现 %d 个潜在风险文件，请立即审查", len(records)-1)
	cr.Details = "以下是河马工具报告的风险文件列表：\n\n" + tableBuilder.String()
	cr.IsSuspicious = true

	return []types.CheckResult{cr}
}
