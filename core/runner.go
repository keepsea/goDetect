package core

import "github.com/keepsea/goDetect/types"

// Checker 是所有检查项都必须实现的接口
type Checker interface {
	Execute() []types.CheckResult
	Name() string // 返回检查项的编程名称，用于查找配置
}
