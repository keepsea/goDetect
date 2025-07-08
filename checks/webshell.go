package checks

import (
	"encoding/csv"
	"fmt"
	"os"
	"strings"

	"github.com/keepsea/goDetect/rules"
	"github.com/keepsea/goDetect/types"
	"github.com/keepsea/goDetect/utils"
)

// --- WebshellCheck ---
type WebshellCheck struct {
	RuleEngine     *rules.RuleEngine
	WebPath        string
	HemaPath       string
	HemaResultPath string
}

func (c WebshellCheck) Name() string { return "WebshellCheck" }
func (c WebshellCheck) Execute() []types.CheckResult {
	cr := types.CheckResult{
		Category: "🌐 Web安全",
	}
	scannerPath := c.HemaPath
	resultFilePath := c.HemaResultPath
	if _, err := os.Stat(scannerPath); os.IsNotExist(err) {
		cr.IsSuspicious, cr.Result, cr.Details = true, "扫描失败", "未在当前目录下找到河马工具 'hm'。"
		return []types.CheckResult{cr}
	}
	os.Remove(resultFilePath)
	_, err := utils.RunCommand(scannerPath, "scan", c.WebPath, "--output", resultFilePath)
	if err != nil {
		cr.IsSuspicious, cr.Result, cr.Details = true, "扫描命令执行失败", fmt.Sprintf("执行 '%s scan %s' 时发生错误: %s", scannerPath, c.WebPath, err.Error())
		return []types.CheckResult{cr}
	}
	defer os.Remove(resultFilePath)
	csvFile, err := os.Open(resultFilePath)
	if os.IsNotExist(err) {
		cr.IsSuspicious, cr.Result = false, "扫描完成，未发现风险文件"
		return []types.CheckResult{cr}
	}
	if err != nil {
		cr.IsSuspicious, cr.Result, cr.Details = true, "无法打开结果文件", "无法打开 result.csv: "+err.Error()
		return []types.CheckResult{cr}
	}
	defer csvFile.Close()
	reader := csv.NewReader(csvFile)
	records, err := reader.ReadAll()
	if err != nil {
		cr.IsSuspicious, cr.Result, cr.Details = true, "无法解析结果文件", "无法解析 result.csv: "+err.Error()
		return []types.CheckResult{cr}
	}
	if len(records) <= 1 {
		cr.IsSuspicious, cr.Result = false, "扫描完成，未在结果中发现风险项"
		return []types.CheckResult{cr}
	}
	var tableBuilder strings.Builder
	tableBuilder.WriteString("| " + strings.Join(records[0], " | ") + " |\n")
	tableBuilder.WriteString("|" + strings.Repeat(" --- |", len(records[0])) + "\n")
	for _, row := range records[1:] {
		tableBuilder.WriteString("| " + strings.Join(row, " | ") + " |\n")
	}
	cr.IsSuspicious, cr.Result = true, fmt.Sprintf("发现 %d 个潜在风险文件", len(records)-1)
	cr.Details = "以下是河马工具报告的风险文件列表：\n\n" + tableBuilder.String()
	return []types.CheckResult{cr}
}
