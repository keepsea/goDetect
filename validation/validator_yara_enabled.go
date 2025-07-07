//go:build yara

package validation

import (
	"fmt"
	"os"
	"path/filepath"

	yara "github.com/hillu/go-yara/v4"
)

// validateYaraRules 在启用YARA时，执行真正的YARA规则验证
func validateYaraRules(rulesDir string) int {
	var errorCount int
	yaraFiles, _ := filepath.Glob(filepath.Join(rulesDir, "*.yar"))
	yaraFiles = append(yaraFiles, filepath.Join(rulesDir, "*.yara"))

	if len(yaraFiles) > 0 {
		compiler, err := yara.NewCompiler()
		if err != nil {
			fmt.Println("  ERROR: Could not create YARA compiler. Is YARA library installed correctly?")
			errorCount++
			return errorCount
		}
		for _, filePath := range yaraFiles {
			if filePath == "" {
				continue
			}
			fmt.Printf("Validating YARA file: %s\n", filePath)
			f, err := os.Open(filePath)
			if err != nil {
				fmt.Printf("  ERROR: Failed to read file: %v\n", err)
				errorCount++
				continue
			}
			err = compiler.AddFile(f, filepath.Base(filePath))
			f.Close()
			if err != nil {
				fmt.Printf("  ERROR: YARA syntax error: %v\n", err)
				errorCount++
			}
		}
	}
	return errorCount
}
