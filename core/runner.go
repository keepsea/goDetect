//==============================================================================
// core/runner.go - 定义检查器接口和执行逻辑
//==============================================================================

package core

import "github.com/keepsea/goDetect/types"

// Checker 是所有检查项都必须实现的接口
type Checker interface {
	Execute() []types.CheckResult
}
