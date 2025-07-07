// ==============================================================================
// main.go - 程序主入口
// ==============================================================================
package main

import (
	"bufio"
	"flag"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/keepsea/goDetect/checks"
	"github.com/keepsea/goDetect/core"
	"github.com/keepsea/goDetect/report"
	"github.com/keepsea/goDetect/types"
	"github.com/keepsea/goDetect/utils"
)

func getOSInfo() (string, error) {
	content, err := ioutil.ReadFile("/etc/os-release")
	if err == nil {
		scanner := strings.NewReader(string(content))
		bufScanner := bufio.NewScanner(scanner)
		for bufScanner.Scan() {
			line := bufScanner.Text()
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				return strings.Trim(strings.Split(line, "=")[1], `"`), nil
			}
		}
	}
	return utils.RunCommand("uname", "-a")
}

func main() {
	// --- 1. 解析命令行参数 ---
	webPath := flag.String("webpath", "", "要扫描Webshell的Web目录绝对路径 (例如: /var/www/html)")
	flag.Parse()

	// --- 2. 初始化报告数据 ---
	reportData := types.ReportData{
		Timestamp:   time.Now().Format("2006-01-02 15:04:05 MST"),
		GeneratedBy: "Kylin Host Compromise Check Tool v7 (Optimized)",
	}
	hostname, err := os.Hostname()
	if err == nil {
		reportData.Hostname = hostname
	}
	osInfo, err := getOSInfo()
	if err == nil {
		reportData.OSInfo = osInfo
	}

	// --- 3. 注册所有需要执行的检查项 ---
	checksToRun := []core.Checker{
		// 账号安全
		checks.RootAccountsCheck{},
		checks.EmptyPasswordAccountsCheck{},
		checks.SudoersCheck{},
		checks.LastLoginsCheck{},
		checks.FailedLoginsCheck{},
		// ** NEW ** 命令历史
		checks.HistoryCheck{},
		// 进程与服务
		checks.SuspiciousProcessesCheck{},
		checks.DeletedRunningProcessesCheck{},
		// 网络连接
		checks.ListeningPortsCheck{},
		checks.EstablishedConnectionsCheck{}, // ** NEW **
		checks.PromiscuousModeCheck{},
		// 文件系统
		checks.SuidSgidFilesCheck{},
		checks.RecentlyModifiedFilesCheck{Path: "/etc", Days: 7},
		checks.TempDirsCheck{},
		// 持久化机制
		checks.CronJobsCheck{},
		checks.SystemdTimersCheck{},
		// 内核与模块
		checks.KernelModulesCheck{},
	}
	// 如果指定了webpath，则添加webshell检查
	if *webPath != "" {
		checksToRun = append(checksToRun, checks.WebshellCheck{WebPath: *webPath})
	}

	// --- 4. 执行所有检查并收集结果 ---
	var allResults []types.CheckResult
	for _, chk := range checksToRun {
		results := chk.Execute()
		allResults = append(allResults, results...)
	}
	// 如果没有指定webpath，也添加一条跳过记录
	if *webPath == "" {
		allResults = append(allResults, types.CheckResult{
			Category: "🌐 Web安全", Description: "Webshell 检测", Result: "[跳过]",
			Details: "未通过 -webpath 参数指定Web目录，已跳过 Webshell 检测。",
		})
	}

	// --- 5. 分类结果 ---
	for _, check := range allResults {
		if check.NeedsManual {
			reportData.ManualChecks = append(reportData.ManualChecks, check)
			if check.IsSuspicious {
				reportData.SuspiciousCount++
			}
			reportData.ManualReviewCount++
		} else {
			reportData.Checks = append(reportData.Checks, check)
			if check.IsSuspicious {
				reportData.SuspiciousCount++
			}
		}
	}
	reportData.TotalChecks = len(allResults)

	// --- 6. 生成报告 ---
	report.GenerateReport(reportData)
}
