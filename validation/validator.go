// FILE: validation/validator.go
package validation

import (
	"fmt"
	"io/ioutil"
	"path/filepath"
	"regexp"

	"gopkg.in/yaml.v3"
)

// Rule 和 IOC 结构体定义，仅用于验证，与 rules/engine.go 解耦
type Rule struct {
	Name        string   `yaml:"name"`
	Enabled     bool     `yaml:"enabled"`
	TargetCheck string   `yaml:"target_check"`
	Type        string   `yaml:"type"`
	Patterns    []string `yaml:"patterns"`
	Pattern     string   `yaml:"pattern"`
}

type RuleFile struct {
	Rules []Rule `yaml:"rules"`
}

type IOC struct {
	Name       string   `yaml:"name"`
	Enabled    bool     `yaml:"enabled"`
	Type       string   `yaml:"type"`
	MatchType  string   `yaml:"match_type"`
	Indicators []string `yaml:"indicators"`
}

type IOCFile struct {
	IOCs []IOC `yaml:"iocs"`
}

// ValidateRules 是验证功能的主函数
func ValidateRules(rulesDir string, iocPath string) bool {
	fmt.Println("--- Starting Rule and IOC Validation ---")
	var errorCount int

	// 1. 验证 YAML 规则文件
	yamlFiles, _ := filepath.Glob(filepath.Join(rulesDir, "*.yaml"))
	ymlFiles, _ := filepath.Glob(filepath.Join(rulesDir, "*.yml"))
	yamlFiles = append(yamlFiles, ymlFiles...)

	for _, filePath := range yamlFiles {
		if filePath == "" {
			continue
		}
		fmt.Printf("Validating YAML file: %s\n", filePath)
		yamlFile, err := ioutil.ReadFile(filePath)
		if err != nil {
			fmt.Printf("  ERROR: Failed to read file: %v\n", err)
			errorCount++
			continue
		}

		var ruleFile RuleFile
		err = yaml.Unmarshal(yamlFile, &ruleFile)
		if err != nil {
			fmt.Printf("  ERROR: YAML syntax error: %v\n", err)
			errorCount++
			continue
		}

		for i, rule := range ruleFile.Rules {
			if !rule.Enabled {
				continue
			}
			// 验证正则表达式
			if rule.Type == "regex" || rule.Type == "agg_regex" {
				patterns := rule.Patterns
				if rule.Type == "agg_regex" {
					patterns = []string{rule.Pattern}
				}
				for _, p := range patterns {
					if p == "" {
						continue
					}
					_, err := regexp.Compile(p)
					if err != nil {
						fmt.Printf("  ERROR: Rule #%d ('%s') has an invalid regex pattern '%s': %v\n", i+1, rule.Name, p, err)
						errorCount++
					}
				}
			}
		}
	}

	// 2. 调用YARA验证函数 (它将在其他文件中被定义)
	yaraErrorCount := validateYaraRules(rulesDir)
	errorCount += yaraErrorCount

	// 3. 验证 IOC 文件
	fmt.Printf("Validating IOC file: %s\n", iocPath)
	iocFileContent, err := ioutil.ReadFile(iocPath)
	if err != nil {
		fmt.Printf("  ERROR: Failed to read file: %v\n", err)
		errorCount++
	} else {
		var iocFile IOCFile
		err = yaml.Unmarshal(iocFileContent, &iocFile)
		if err != nil {
			fmt.Printf("  ERROR: YAML syntax error in IOC file: %v\n", err)
			errorCount++
		}
	}

	fmt.Println("--- Validation Finished ---")
	if errorCount > 0 {
		fmt.Printf("Result: Found %d error(s).\n", errorCount)
		return false
	}

	fmt.Println("Result: All rule and IOC files are valid.")
	return true
}
