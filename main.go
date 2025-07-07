// ==============================================================================
// main.go - 程序主入口
// ==============================================================================
// FILE: main.go (根目录)
package main

import (
	"bufio"
	"flag"
	"fmt"
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

const (
	Version = "v9.0 (Progress Bar)"
	Banner  = "\n" +
		"   ____        ____       _        _   _             \n" +
		"  / ___|  ___ |  _ \\  ___| |_ __ _| |_(_) ___  _ __  \n" +
		" | |  _  / _ \\| | | |/ _ \\ __/ _` | __| |/ _ \\| '_ \\ \n" +
		" | |_| ||  __/| |_| |  __/ || (_| | |_| | (_) | | | |\n" +
		"  \\____| \\___||____/ \\___|\\__\\__,_|\\__|_|\\___/|_| |_|\n" +
		"\n"
)

func getOSInfo() (string, error) {
	// ... (代码逻辑不变) ...
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
	// --- 打印启动 Banner ---
	fmt.Println(Banner)
	fmt.Printf("      Host Compromise Check Tool - Version %s\n", Version)
	fmt.Println("==========================================================")

	// --- 1. 解析命令行参数 ---
	webPath := flag.String("webpath", "", "要扫描Webshell的Web目录绝对路径 (例如: /var/www/html)")
	flag.Parse()

	// --- 2. 初始化报告数据 ---
	reportData := types.ReportData{
		Timestamp:   time.Now().Format("2006-01-02 15:04:05 MST"),
		GeneratedBy: "Kylin Host Compromise Check Tool " + Version,
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
		checks.RootAccountsCheck{},
		checks.EmptyPasswordAccountsCheck{},
		checks.SudoersCheck{},
		checks.LastLoginsCheck{},
		checks.FailedLoginsCheck{},
		checks.HistoryCheck{},
		checks.SuspiciousProcessesCheck{},
		checks.DeletedRunningProcessesCheck{},
		checks.ListeningPortsCheck{},
		checks.EstablishedConnectionsCheck{},
		checks.PromiscuousModeCheck{},
		checks.SuidSgidFilesCheck{},
		checks.RecentlyModifiedFilesCheck{Path: "/etc", Days: 7},
		checks.TempDirsCheck{},
		checks.CronJobsCheck{},
		checks.SystemdTimersCheck{},
		checks.KernelModulesCheck{},
	}
	if *webPath != "" {
		checksToRun = append(checksToRun, checks.WebshellCheck{WebPath: *webPath})
	}

	// --- 4. ** MODIFIED ** 执行所有检查并打印进度 ---
	fmt.Println("\n--- Starting Checks ---")
	var allResults []types.CheckResult
	totalChecks := len(checksToRun)
	for i, chk := range checksToRun {
		fmt.Printf("[%d/%d] Executing: %-45s", i+1, totalChecks, chk.Description())
		results := chk.Execute()
		allResults = append(allResults, results...)
		fmt.Println("Done.")
	}
	fmt.Println("--- All Checks Completed ---")

	// --- 5. 统计结果 ---
	reportData.Checks = allResults // 将所有结果放入一个列表
	reportData.TotalChecks = len(allResults)
	for _, check := range allResults {
		if check.IsSuspicious {
			reportData.SuspiciousCount++
		}
		if check.NeedsManual {
			reportData.ManualReviewCount++
		}
	}

	// --- 6. 生成报告 ---
	fmt.Println("\nScan complete. Generating report...")
	report.GenerateReport(reportData)
}
