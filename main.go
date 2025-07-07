package main

import (
	"bufio"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"sync"
	"sync/atomic" // ** NEW **: 引入原子操作包
	"time"

	"github.com/keepsea/goDetect/checks"
	"github.com/keepsea/goDetect/core"
	"github.com/keepsea/goDetect/report"
	"github.com/keepsea/goDetect/rules"
	"github.com/keepsea/goDetect/types"
	"github.com/keepsea/goDetect/utils"
)

const (
	Version = "v15.0 (Progress Bar)" // ** MODIFIED **
	Banner  = "\n" +
		"   ____        ____       _        _   _             \n" +
		"  / ___|  ___ |  _ \\  ___| |_ __ _| |_(_) ___  _ __  \n" +
		" | |  _  / _ \\| | | |/ _ \\ __/ _` | __| |/ _ \\| '_ \\ \n" +
		" | |_| ||  __/| |_| |  __/ || (_| | |_| | (_) | | | |\n" +
		"  \\____| \\___||____/ \\___|\\__\\__,_|\\__|_|\\___/|_| |_|\n" +
		"\n"
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
	fmt.Print(Banner)
	fmt.Printf("      Host Compromise Check Tool - Version %s\n", Version)
	fmt.Println("==========================================================")

	// --- 定义命令行参数 ---
	webPath := flag.String("webpath", "", "要扫描Webshell的Web目录绝对路径")
	loginLimit := flag.Int("login-limit", 50, "要审计的最近登录记录条数")
	mtimeDays := flag.Int("mtime-days", 7, "要检查的近期文件修改天数范围")
	mtimePath := flag.String("mtime-path", "/etc", "要检查的近期文件修改路径")
	suidDirs := flag.String("suid-dirs", "/", "要扫描SUID/SGID文件的目录 (逗号分隔)")
	flag.Parse()

	// --- 初始化规则引擎和报告数据 ---
	ruleEngine, err := rules.NewRuleEngine("./rules", "./ioc.yaml")
	if err != nil {
		fmt.Printf("严重错误: 规则引擎初始化失败: %v\n", err)
		os.Exit(1)
	}

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

	// --- 使用参数来初始化检查项 ---
	checksToRun := []core.Checker{
		checks.RootAccountsCheck{RuleEngine: ruleEngine},
		checks.EmptyPasswordAccountsCheck{RuleEngine: ruleEngine},
		checks.SudoersCheck{RuleEngine: ruleEngine},
		checks.LastLoginsCheck{RuleEngine: ruleEngine, Limit: *loginLimit},
		checks.FailedLoginsCheck{RuleEngine: ruleEngine},
		checks.HistoryCheck{RuleEngine: ruleEngine},
		checks.SuspiciousProcessesCheck{RuleEngine: ruleEngine},
		checks.DeletedRunningProcessesCheck{RuleEngine: ruleEngine},
		checks.ListeningPortsCheck{RuleEngine: ruleEngine},
		checks.EstablishedConnectionsCheck{RuleEngine: ruleEngine},
		checks.PromiscuousModeCheck{RuleEngine: ruleEngine},
		checks.SuidSgidFilesCheck{RuleEngine: ruleEngine, Dirs: strings.Split(*suidDirs, ",")},
		checks.RecentlyModifiedFilesCheck{RuleEngine: ruleEngine, Path: *mtimePath, Days: *mtimeDays},
		checks.TempDirsCheck{RuleEngine: ruleEngine},
		checks.CronJobsCheck{RuleEngine: ruleEngine},
		checks.SystemdTimersCheck{RuleEngine: ruleEngine},
		checks.KernelModulesCheck{RuleEngine: ruleEngine},
	}
	if *webPath != "" {
		checksToRun = append(checksToRun, checks.WebshellCheck{RuleEngine: ruleEngine, WebPath: *webPath})
	}

	// --- 修改开始 ---
	// --- 并发执行和报告生成的逻辑 ---
	fmt.Println("\n--- Starting Checks ---")
	var allResults []types.CheckResult
	var wg sync.WaitGroup
	resultsChan := make(chan []types.CheckResult, len(checksToRun))

	var completedChecks int32 // ** NEW **: 用于原子计数的变量
	totalChecks := len(checksToRun)

	for _, chk := range checksToRun {
		wg.Add(1)
		go func(c core.Checker) {
			defer wg.Done()
			// 执行检查
			results := c.Execute()
			resultsChan <- results

			// ** NEW **: 更新并打印进度
			atomic.AddInt32(&completedChecks, 1)
			currentCount := atomic.LoadInt32(&completedChecks)
			percent := (float64(currentCount) / float64(totalChecks)) * 100
			fmt.Printf("✔ [%d/%d] (%.0f%%) Completed: %s\n", currentCount, totalChecks, percent, c.Description())

		}(chk)
	}

	wg.Wait()
	close(resultsChan)

	for res := range resultsChan {
		allResults = append(allResults, res...)
	}
	fmt.Println("--- All Checks Completed ---")
	// --- 修改结束 ---

	if *webPath == "" {
		allResults = append(allResults, types.CheckResult{
			Category:    "🌐 Web安全",
			Description: "Webshell 检测",
			Result:      "[跳过]",
			Explanation: "通过 `-webpath` 参数可以指定Web目录，以启用此项检查。",
			Details:     "未提供 -webpath 参数，已跳过 Webshell 检测。",
		})
	}

	reportData.Checks = allResults
	reportData.TotalChecks = len(allResults)
	var suspiciousCount int
	for _, check := range allResults {
		if check.IsSuspicious {
			suspiciousCount++
		}
	}
	reportData.SuspiciousCount = suspiciousCount

	fmt.Println("\nScan complete. Generating report...")
	report.GenerateReport(reportData)
}
