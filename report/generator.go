//==============================================================================
// report/generator.go - 报告生成器
//==============================================================================

package report

import (
	"fmt"
	"html/template"
	"os"
	"time"

	"github.com/keepsea/goDetect/types"
)

// GenerateReport 使用模板生成 Markdown 报告并保存到文件
func GenerateReport(data types.ReportData) {
	reportTemplate := `
# 主机失陷检测报告

## 1. 报告摘要

- **主机名:** {{.Hostname}}
- **操作系统:** {{.OSInfo}}
- **检测时间:** {{.Timestamp}}
- **生成工具:** {{.GeneratedBy}}
- **总检查项:** {{.TotalChecks}}
- **发现可疑项:** {{.SuspiciousCount}}
- **待人工确认项:** {{.ManualReviewCount}}

---

## 2. 自动检测结果

本部分列出了程序根据预设规则判断的结果。标记为 **[可疑]** 的项目需要您特别关注。

{{range .Checks}}
### {{.Category}} - {{.Description}}

- **结果:** {{if .IsSuspicious}}**[可疑]** {{else}}{{if eq .Result "[跳过]"}}**[跳过]**{{else}}[正常]{{end}}{{end}} {{.Result}}
{{if or .IsSuspicious (eq .Result "[跳过]")}}
<details>
<summary>点击查看详细信息</summary>

` + "```" + `
{{.Details}}
` + "```" + `

</details>
{{end}}
---
{{end}}

## 3. 待人工确认项

本部分列出的项目程序无法自动判断其是否异常，**需要您根据业务场景和系统正常状态进行人工审计**。这些项目本身不一定代表失陷，但攻击者常在这些地方留下痕迹。

{{range .ManualChecks}}
### {{.Category}} - {{.Description}}

- **说明:** {{.Result}}

<details>
<summary>点击展开详细审计数据</summary>

` + "```" + `
{{.Details}}
` + "```" + `

</details>

---
{{end}}
`
	fileName := fmt.Sprintf("host_check_report_%s_%s.md", data.Hostname, time.Now().Format("20060102150405"))
	tmpl, err := template.New("report").Parse(reportTemplate)
	if err != nil {
		fmt.Println("错误：创建报告模板失败:", err)
		return
	}
	file, err := os.Create(fileName)
	if err != nil {
		fmt.Println("错误：创建报告文件失败:", err)
		return
	}
	defer file.Close()
	err = tmpl.Execute(file, data)
	if err != nil {
		fmt.Println("错误：生成报告失败:", err)
		return
	}
	fmt.Printf("检测完成！报告已生成到当前目录下的文件: %s\n", fileName)
}
