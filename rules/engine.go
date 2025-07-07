// FILE: rules/engine.go
package rules

import (
	"fmt"
	"io/ioutil"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	yara "github.com/hillu/go-yara/v4"
	"gopkg.in/yaml.v3"
)

// Rule 定义了单条检测规则的结构
type Rule struct {
	Name                string           `yaml:"name"`
	Enabled             bool             `yaml:"enabled"`
	Description         string           `yaml:"description"`
	TargetCheck         string           `yaml:"target_check"`
	Type                string           `yaml:"type"`
	Patterns            []string         `yaml:"patterns"`
	Pattern             string           `yaml:"pattern"`
	Condition           string           `yaml:"condition"`
	RiskLevel           string           `yaml:"risk_level"`
	precompiledPatterns []*regexp.Regexp `yaml:"-"`
}

// RuleFile 定义了规则文件的结构
type RuleFile struct {
	Rules []Rule `yaml:"rules"`
}

// IOC 定义了威胁情报的结构
type IOC struct {
	Name                  string           `yaml:"name"`
	Enabled               bool             `yaml:"enabled"`
	Type                  string           `yaml:"type"`
	Description           string           `yaml:"description"`
	MatchType             string           `yaml:"match_type"`
	Indicators            []string         `yaml:"indicators"`
	precompiledIndicators []*regexp.Regexp `yaml:"-"`
}

// IOCFile 定义了威胁情报文件的结构
type IOCFile struct {
	IOCs []IOC `yaml:"iocs"`
}

// RuleEngine 是规则引擎的核心结构
type RuleEngine struct {
	rulesByCheck map[string][]Rule
	iocsByType   map[string][]IOC
	yaraCompiler *yara.Compiler
}

// Finding 代表一个由规则或IOC匹配产生的风险发现
type Finding struct {
	Source      string // "Rule", "IOC", or "YARA"
	Name        string
	Description string
	RiskLevel   string
	MatchedLine string
}

// NewRuleEngine 创建并初始化一个新的规则引擎
func NewRuleEngine(rulesDir string, iocPath string) (*RuleEngine, error) {
	engine := &RuleEngine{
		rulesByCheck: make(map[string][]Rule),
		iocsByType:   make(map[string][]IOC),
	}

	// 调用 initYara, Go会根据构建标签自动选择正确的版本
	// 这个函数在 yara_enabled.go 或 yara_disabled.go 中定义
	initYara(engine, rulesDir)

	// --- 加载 YAML 规则文件 ---
	files, err := ioutil.ReadDir(rulesDir)
	if err != nil {
		return nil, fmt.Errorf("无法读取规则目录 '%s': %w", rulesDir, err)
	}

	for _, file := range files {
		if filepath.Ext(file.Name()) == ".yaml" || filepath.Ext(file.Name()) == ".yml" {
			filePath := filepath.Join(rulesDir, file.Name())
			yamlFile, err := ioutil.ReadFile(filePath)
			if err != nil {
				fmt.Printf("警告: 无法读取规则文件 '%s', 已跳过: %v\n", filePath, err)
				continue
			}

			var ruleFile RuleFile
			err = yaml.Unmarshal(yamlFile, &ruleFile)
			if err != nil {
				fmt.Printf("警告: 无法解析规则文件 '%s', 已跳过: %v\n", filePath, err)
				continue
			}

			for i := range ruleFile.Rules {
				rule := &ruleFile.Rules[i]
				if !rule.Enabled {
					continue
				}

				// 规则预编译
				if rule.Type == "regex" {
					for _, p := range rule.Patterns {
						re, err := regexp.Compile(p)
						if err != nil {
							fmt.Printf("警告: 编译规则 '%s' 的正则表达式 '%s' 失败, 已跳过: %v\n", rule.Name, p, err)
							continue
						}
						rule.precompiledPatterns = append(rule.precompiledPatterns, re)
					}
				} else if rule.Type == "agg_regex" {
					re, err := regexp.Compile(rule.Pattern)
					if err != nil {
						fmt.Printf("警告: 编译规则 '%s' 的正则表达式 '%s' 失败, 已跳过: %v\n", rule.Name, rule.Pattern, err)
						continue
					}
					rule.precompiledPatterns = []*regexp.Regexp{re}
				}
				// 规则分组
				engine.rulesByCheck[rule.TargetCheck] = append(engine.rulesByCheck[rule.TargetCheck], *rule)
			}
		}
	}

	// --- 加载 IOC 文件 ---
	iocFileContent, err := ioutil.ReadFile(iocPath)
	if err != nil {
		fmt.Printf("警告: 无法读取威胁情报文件 '%s', IOC功能将不可用: %v\n", iocPath, err)
	} else {
		var iocFile IOCFile
		err = yaml.Unmarshal(iocFileContent, &iocFile)
		if err != nil {
			fmt.Printf("警告: 无法解析威胁情报文件 '%s', IOC功能将不可用: %v\n", iocPath, err)
		} else {
			for i := range iocFile.IOCs {
				ioc := &iocFile.IOCs[i]
				if !ioc.Enabled {
					continue
				}
				if ioc.MatchType == "regex" {
					for _, indicator := range ioc.Indicators {
						re, err := regexp.Compile(indicator)
						if err != nil {
							fmt.Printf("警告: 编译IOC '%s' 的正则表达式 '%s' 失败, 已跳过: %v\n", ioc.Name, indicator, err)
							continue
						}
						ioc.precompiledIndicators = append(ioc.precompiledIndicators, re)
					}
				}
				engine.iocsByType[ioc.Type] = append(engine.iocsByType[ioc.Type], *ioc)
			}
		}
	}

	return engine, nil
}

// MatchIOC 对给定的文本内容执行IOC匹配
func (e *RuleEngine) MatchIOC(iocType string, content string) []Finding {
	var findings []Finding
	iocs, ok := e.iocsByType[iocType]
	if !ok {
		return findings
	}

	for _, ioc := range iocs {
		if ioc.MatchType == "regex" {
			for _, re := range ioc.precompiledIndicators {
				if re.MatchString(content) {
					findings = append(findings, Finding{
						Source:      "IOC",
						Name:        ioc.Name,
						Description: ioc.Description,
						RiskLevel:   "High", // IOC匹配通常风险较高
						MatchedLine: fmt.Sprintf("匹配到正则指标 '%s' -> %s", re.String(), content),
					})
				}
			}
		} else { // 默认为 keyword
			for _, indicator := range ioc.Indicators {
				if strings.Contains(content, indicator) {
					findings = append(findings, Finding{
						Source:      "IOC",
						Name:        ioc.Name,
						Description: ioc.Description,
						RiskLevel:   "High",
						MatchedLine: fmt.Sprintf("匹配到关键词指标 '%s' -> %s", indicator, content),
					})
				}
			}
		}
	}
	return findings
}

// Match 对给定的文本内容执行匹配
func (e *RuleEngine) Match(checkName string, content string) []Finding {
	var findings []Finding
	rules, ok := e.rulesByCheck[checkName]
	if !ok {
		return findings
	}

	lines := strings.Split(content, "\n")

	for _, rule := range rules {
		switch rule.Type {
		case "keyword":
			for _, line := range lines {
				for _, pattern := range rule.Patterns {
					if strings.Contains(line, pattern) {
						findings = append(findings, Finding{
							Source:      "Rule",
							Name:        rule.Name,
							Description: rule.Description,
							RiskLevel:   rule.RiskLevel,
							MatchedLine: line,
						})
						break
					}
				}
			}
		case "regex":
			for _, line := range lines {
				for _, re := range rule.precompiledPatterns {
					if re.MatchString(line) {
						findings = append(findings, Finding{
							Source:      "Rule",
							Name:        rule.Name,
							Description: rule.Description,
							RiskLevel:   rule.RiskLevel,
							MatchedLine: line,
						})
						break
					}
				}
			}
		case "agg_regex":
			counts := make(map[string]int)
			if len(rule.precompiledPatterns) == 0 {
				continue
			}
			re := rule.precompiledPatterns[0]
			for _, line := range lines {
				matches := re.FindStringSubmatch(line)
				if len(matches) > 1 {
					counts[matches[1]]++
				}
			}

			parts := strings.Fields(rule.Condition)
			if len(parts) == 3 && parts[0] == "count" {
				threshold, err := strconv.Atoi(parts[2])
				if err != nil {
					continue
				}

				for entity, count := range counts {
					trigger := false
					switch parts[1] {
					case ">":
						if count > threshold {
							trigger = true
						}
					case "<":
						if count < threshold {
							trigger = true
						}
					case "==":
						if count == threshold {
							trigger = true
						}
					}
					if trigger {
						findings = append(findings, Finding{
							Source:      "Rule",
							Name:        rule.Name,
							Description: rule.Description,
							RiskLevel:   rule.RiskLevel,
							MatchedLine: fmt.Sprintf("实体 '%s' 出现 %d 次, 触发条件 '%s'", entity, count, rule.Condition),
						})
					}
				}
			}
		}
	}
	return findings
}
