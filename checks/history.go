package checks

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/keepsea/goDetect/types"
)

// HistoryCheck 检查所有用户的命令历史
type HistoryCheck struct{}

func (c HistoryCheck) Execute() []types.CheckResult {
	cr := types.CheckResult{
		Category:     "📝 命令历史",
		Description:  "检查所有用户的命令历史记录",
		NeedsManual:  true,
		IsSuspicious: true, // 总是标记为需要人工审计
	}

	var details strings.Builder
	suspiciousKeywords := []string{"wget", "curl", "nc ", "ncat", "base64", "chmod +x"}
	var suspiciousCommands []string

	passwdFile, err := os.Open("/etc/passwd")
	if err != nil {
		cr.Result = "检查失败"
		cr.Details = "无法打开 /etc/passwd 文件: " + err.Error()
		return []types.CheckResult{cr}
	}
	defer passwdFile.Close()

	scanner := bufio.NewScanner(passwdFile)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ":")
		if len(parts) < 6 {
			continue
		}
		username := parts[0]
		homeDir := parts[5]

		// 尝试多个常见的 history 文件名
		historyFiles := []string{".bash_history", ".zsh_history", ".history"}
		for _, hf := range historyFiles {
			historyPath := filepath.Join(homeDir, hf)
			if _, err := os.Stat(historyPath); os.IsNotExist(err) {
				continue
			}

			// 尝试以root权限读取，如果不行则以当前用户权限
			content, err := readHistoryAsRootOrUser(historyPath, username)
			if err != nil {
				continue // 忽略读取失败的文件
			}

			details.WriteString(fmt.Sprintf("\n--- 用户 '%s' 的历史记录 (%s) ---\n", username, historyPath))
			details.WriteString(string(content))
			details.WriteString("\n")

			// 检查可疑关键词
			historyScanner := bufio.NewScanner(strings.NewReader(string(content)))
			for historyScanner.Scan() {
				cmdLine := historyScanner.Text()
				for _, keyword := range suspiciousKeywords {
					if strings.Contains(cmdLine, keyword) {
						suspiciousCommands = append(suspiciousCommands, fmt.Sprintf("用户 '%s': %s", username, cmdLine))
						break // 找到一个关键词就够了
					}
				}
			}
		}
	}

	if len(suspiciousCommands) > 0 {
		cr.Result = fmt.Sprintf("发现 %d 条可疑命令，需人工确认", len(suspiciousCommands))
		var summary strings.Builder
		summary.WriteString("在命令历史中发现以下可疑命令:\n")
		for _, cmd := range suspiciousCommands {
			summary.WriteString(cmd + "\n")
		}
		summary.WriteString("\n\n" + details.String())
		cr.Details = summary.String()
	} else {
		cr.Result = "未自动发现可疑关键词，但仍建议人工审计全部历史记录"
		cr.Details = details.String()
	}

	return []types.CheckResult{cr}
}

// readHistoryAsRootOrUser 尝试以root身份读取文件，如果失败则尝试切换到指定用户读取
// 注意：这个函数在实际中可能因权限问题受限，这里做简化处理，主要依赖以高权限运行本程序
func readHistoryAsRootOrUser(path, username string) ([]byte, error) {
	// 简化逻辑：直接读取。依赖于本程序是以root权限运行的。
	// 在一个非root程序中，要读取其他用户的文件需要更复杂的权限操作。
	content, err := ioutil.ReadFile(path)
	if err != nil {
		// 如果以root都读不了（例如文件权限为000），那就没办法了
		return nil, err
	}
	return content, nil
}
