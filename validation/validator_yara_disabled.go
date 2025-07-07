//go:build !yara

package validation

import "fmt"

// validateYaraRules 在禁用YARA时，打印跳过信息
func validateYaraRules(rulesDir string) int {
	fmt.Println("Skipping YARA rule validation: build tag 'yara' is not set.")
	return 0
}
