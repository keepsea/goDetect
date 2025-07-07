package checks

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/keepsea/goDetect/rules"
	"github.com/keepsea/goDetect/types"
)

// HistoryCheck 检查所有用户的命令历史
type HistoryCheck struct {
	RuleEngine *rules.RuleEngine
	Filenames  []string
}

func (c HistoryCheck) Description() string { return "检查所有用户的命令历史记录" }
func (c HistoryCheck) Execute() []types.CheckResult {
	cr := types.CheckResult{
		Category:    "📝 命令历史",
		Description: c.Description(),
		Explanation: "作用: 命令历史直接揭示了攻击者可能执行过的操作，是追溯攻击路径的关键证据。\n检查方法: 读取所有用户主目录下的指定历史文件。\n判断依据: 规则引擎会根据 `ioc.yaml` 中 `type: history_keyword` 的规则进行判断。",
	}

	var contentBuilder strings.Builder
	passwdFile, err := os.Open("/etc/passwd")
	if err != nil {
		cr.IsSuspicious, cr.Result, cr.Details = true, "检查失败", "无法打开 /etc/passwd 文件: "+err.Error()
		return []types.CheckResult{cr}
	}
	defer passwdFile.Close()

	scanner := bufio.NewScanner(passwdFile)
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), ":")
		if len(parts) < 6 {
			continue
		}
		username, homeDir := parts[0], parts[5]

		// 使用可配置的文件名列表
		for _, hf := range c.Filenames {
			historyPath := filepath.Join(homeDir, hf)
			if _, err := os.Stat(historyPath); os.IsNotExist(err) {
				continue
			}
			content, err := ioutil.ReadFile(historyPath)
			if err == nil {
				contentBuilder.WriteString(fmt.Sprintf("\n--- 用户 '%s' (%s) ---\n%s", username, historyPath, string(content)))
			}
		}
	}
	cr.Details = contentBuilder.String()

	// 调用IOC引擎匹配关键词
	historyScanner := bufio.NewScanner(strings.NewReader(cr.Details))
	for historyScanner.Scan() {
		line := historyScanner.Text()
		// 注意: 我们假设IOC的type是 'history_keyword'
		findings := c.RuleEngine.MatchIOC("history_keyword", line)
		cr.Findings = append(cr.Findings, findings...)
	}

	if len(cr.Findings) > 0 {
		cr.IsSuspicious, cr.Result = true, fmt.Sprintf("发现 %d 条可疑的命令历史", len(cr.Findings))
	} else {
		cr.IsSuspicious, cr.Result = false, "未发现可疑的命令历史"
	}
	return []types.CheckResult{cr}
}
