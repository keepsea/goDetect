package types

import "github.com/keepsea/goDetect/rules"

// ReportData 结构体用于存储所有检测结果，并传递给模板
type ReportData struct {
	Timestamp       string
	OSInfo          string
	Hostname        string
	Checks          []CheckResult
	GeneratedBy     string
	TotalChecks     int
	SuspiciousCount int
}

// CheckResult 结构体用于存储单项检查的结果
type CheckResult struct {
	Category     string
	Description  string
	Result       string
	Details      string
	Explanation  string
	IsSuspicious bool
	Findings     []rules.Finding // 用于存放规则匹配结果
}
