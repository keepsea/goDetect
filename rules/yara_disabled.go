//go:build !yara

package rules

// initYara 的存根实现，在禁用YARA时不执行任何操作
func initYara(engine *RuleEngine, rulesDir string) {
	// Do nothing
}

// ScanFileWithYara 的存根实现，在禁用YARA时直接返回空结果
func (e *RuleEngine) ScanFileWithYara(filePath string) []Finding {
	return nil
}
