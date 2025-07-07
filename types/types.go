// ==============================================================================
// types/types.go - 定义项目核心数据结构
// ==============================================================================
package types

// ReportData 结构体用于存储所有检测结果，并传递给模板
type ReportData struct {
	Timestamp         string
	OSInfo            string
	Hostname          string
	Checks            []CheckResult
	ManualChecks      []CheckResult
	GeneratedBy       string
	TotalChecks       int
	SuspiciousCount   int
	ManualReviewCount int
}

// CheckResult 结构体用于存储单项检查的结果
type CheckResult struct {
	Category     string // 检查类别
	Description  string // 检查项描述
	Result       string // 检查结果的简要说明
	Details      string // 详细的原始输出或解释
	Explanation  string // ** NEW **: 对检查项的详细说明
	IsSuspicious bool   // 是否可疑
	NeedsManual  bool   // 是否需要人工确认
}
