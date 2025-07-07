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

// --- HistoryCheck ---
type HistoryCheck struct {
	RuleEngine *rules.RuleEngine
}

func (c HistoryCheck) Description() string { return "检查所有用户的命令历史记录" }
func (c HistoryCheck) Execute() []types.CheckResult {
	cr := types.CheckResult{
		Category: "📝 命令历史", Description: c.Description(),
		Explanation: "作用: 命令历史直接揭示了攻击者可能执行过的操作，是追溯攻击路径的关键证据。\n检查方法: 读取所有用户主目录下的 `.bash_history` 等历史文件。\n判断依据: 规则引擎会根据 `rules/history.yaml` 等文件中的规则（如匹配 `wget`, `curl|sh`, 反弹shell命令等）进行判断。",
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
		historyFiles := []string{".bash_history", ".zsh_history", ".history"}
		for _, hf := range historyFiles {
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
	findings := c.RuleEngine.Match("HistoryCheck", cr.Details)
	cr.Findings = findings

	if len(findings) > 0 {
		cr.IsSuspicious, cr.Result = true, fmt.Sprintf("发现 %d 条可疑的命令历史", len(findings))
	} else {
		cr.IsSuspicious, cr.Result = false, "未发现可疑的命令历史"
	}
	return []types.CheckResult{cr}
}
