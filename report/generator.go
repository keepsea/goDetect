package report

import (
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"time"

	"github.com/keepsea/goDetect/types"
)

// Generator 是所有报告生成器都必须实现的接口
type Generator interface {
	Generate(data types.ReportData, outputDir string) error
}

// --- MarkdownGenerator ---
type MarkdownGenerator struct{}

func (g MarkdownGenerator) Generate(data types.ReportData, outputDir string) error {
	reportTemplate := `
# 主机失陷检测报告

## 1. 报告摘要

- **主机名:** {{.Hostname}}
- **操作系统:** {{.OSInfo}}
- **检测时间:** {{.Timestamp}}
- **生成工具:** {{.GeneratedBy}}
- **总检查项:** {{.TotalChecks}}
- **发现可疑项:** {{.SuspiciousCount}}

---

## 2. 详细检测结果

{{range .Checks}}
### {{.Category}} - {{.Description}}

- **结果:** {{if .IsSuspicious}}**[可疑]**{{else}}[正常]{{end}} {{.Result}}

<details>
<summary>点击展开/折叠详细信息</summary>

#### 检查说明
> {{.Explanation}}

{{if .Findings}}
#### 规则匹配发现 ({{len .Findings}})
` + "```" + `
{{range .Findings}}
[{{.Source}} | 规则: {{.Name}}] [风险: {{.RiskLevel}}]
说明: {{.Description}}
匹配内容: {{.MatchedLine}}
---
{{end}}
` + "```" + `
{{end}}

#### 原始数据
` + "```" + `
{{.Details}}
` + "```" + `

</details>

---
{{end}}
`
	// 确保输出目录存在
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("无法创建报告目录 '%s': %w", outputDir, err)
	}
	fileName := fmt.Sprintf("host_check_report_%s.md", time.Now().Format("20060102150405"))
	filePath := filepath.Join(outputDir, fileName)

	tmpl, err := template.New("report").Parse(reportTemplate)
	if err != nil {
		return fmt.Errorf("创建Markdown模板失败: %w", err)
	}

	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("创建Markdown报告文件失败: %w", err)
	}
	defer file.Close()

	err = tmpl.Execute(file, data)
	if err != nil {
		return fmt.Errorf("生成Markdown报告失败: %w", err)
	}

	fmt.Printf("Markdown报告已生成: %s\n", filePath)
	return nil
}

// --- JsonGenerator ---
type JsonGenerator struct{}

func (g JsonGenerator) Generate(data types.ReportData, outputDir string) error {
	// 确保输出目录存在
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("无法创建报告目录 '%s': %w", outputDir, err)
	}
	fileName := fmt.Sprintf("host_check_report_%s.json", time.Now().Format("20060102150405"))
	filePath := filepath.Join(outputDir, fileName)

	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("创建JSON报告文件失败: %w", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ") // 格式化输出
	err = encoder.Encode(data)
	if err != nil {
		return fmt.Errorf("生成JSON报告失败: %w", err)
	}
	fmt.Printf("JSON报告已生成: %s\n", filePath)
	return nil
}
