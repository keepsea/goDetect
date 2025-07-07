package utils

import (
	"bytes"
	"fmt"
	"os/exec"
)

//==============================================================================
// utils/command.go - 提供通用工具函数
//==============================================================================

// RunCommand 辅助函数，用于执行shell命令并返回其输出
func RunCommand(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("命令执行失败: %s\n错误: %s\n标准错误输出: %s", cmd.String(), err, stderr.String())
	}
	return out.String(), nil
}
