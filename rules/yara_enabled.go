//go:build yara

package rules

import (
	"fmt"
	"os"
	"path/filepath"

	yara "github.com/hillu/go-yara/v4"
)

// initYara 在启用YARA时，负责初始化YARA编译器
func initYara(engine *RuleEngine, rulesDir string) {
	compiler, err := yara.NewCompiler()
	if err != nil {
		fmt.Printf("警告: 无法创建YARA编译器: %v\n", err)
		return
	}

	files, err := os.ReadDir(rulesDir)
	if err != nil {
		return
	}

	for _, file := range files {
		if filepath.Ext(file.Name()) == ".yar" || filepath.Ext(file.Name()) == ".yara" {
			filePath := filepath.Join(rulesDir, file.Name())
			f, err := os.Open(filePath)
			if err == nil {
				compiler.AddFile(f, file.Name())
				f.Close()
			}
		}
	}
	engine.yaraCompiler = compiler
}

// ScanFileWithYara 在启用YARA时，执行真正的文件扫描
func (e *RuleEngine) ScanFileWithYara(filePath string) []Finding {
	var findings []Finding
	if e.yaraCompiler == nil {
		return findings
	}

	rules, err := e.yaraCompiler.GetRules()
	if err != nil {
		return findings
	}

	var matches yara.MatchRules
	err = rules.ScanFile(filePath, 0, 0, &matches)
	if err != nil {
		return findings
	}

	for _, match := range matches {
		findings = append(findings, Finding{
			Source:      "YARA",
			Name:        match.Rule,
			Description: fmt.Sprintf("文件 '%s' 匹配YARA规则", filePath),
			RiskLevel:   "High",
			MatchedLine: fmt.Sprintf("规则: %s, 命名空间: %s", match.Rule, match.Namespace),
		})
	}
	return findings
}
