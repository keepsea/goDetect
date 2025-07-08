package main

import (
	"bufio"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/keepsea/goDetect/checks"
	"github.com/keepsea/goDetect/config"
	"github.com/keepsea/goDetect/core"
	"github.com/keepsea/goDetect/report"
	"github.com/keepsea/goDetect/rules"
	"github.com/keepsea/goDetect/types"
	"github.com/keepsea/goDetect/utils"
	"github.com/keepsea/goDetect/validation"
)

const (
	Version = "v1.0.0 (https://github.com/keepsea/goDetect)"
	Banner  = "\n" +
		"      ,--------------------------,\n" +
		"     |  /---------------------\\  |\n" +
		"     | |                       | |\n" +
		"     | |        /\\_ /\\         | |\n" +
		"     | |       ( o.o )         | |\n" +
		"     | |        > ^ <          | |\n" +
		"     | |                       | |\n" +
		"     |  \\_____________________/  |\n" +
		"     |___________________________|\n" +
		"   ,---\\_____ [by 王权富贵]  ____/--,\n" +
		"  /         `------------------'     \\\n" +
		"  \\__________________________________/\n" +
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
	fmt.Println(Banner)
	fmt.Printf(" GoDetect - Version %s\n", Version)
	fmt.Println("==========================================================")
	fmt.Printf("             安全源自未雨绸缪,隐患常藏字节之间！！!              %s\n")
	fmt.Println("==========================================================")

	// 1. 加载配置文件
	cfg, err := config.LoadConfig()
	if err != nil {
		fmt.Printf("严重错误: 解析配置文件失败: %v\n", err)
		os.Exit(1)
	}

	// 2. 定义所有命令行参数
	validateRules := flag.Bool("validate-rules", false, "只验证规则文件的正确性，不执行扫描")
	outputFormat := flag.String("output", cfg.Output, "报告输出格式 (md, json)")
	memLimitMB := flag.Int64("mem-limit-mb", cfg.MemLimitMB, "设置程序的最大内存使用限制 (MB)，0为不限制")
	reportOutputDir := flag.String("report-dir", cfg.ReportOutputDir, "报告输出目录")
	webPath := flag.String("webpath", cfg.WebPath, "要扫描Webshell的Web目录绝对路径")
	loginLimit := flag.Int("login-limit", cfg.LoginLimit, "要审计的最近登录记录条数")
	mtimeDays := flag.Int("mtime-days", cfg.Mtime.Days, "要检查的近期文件修改天数范围")
	mtimePath := flag.String("mtime-path", cfg.Mtime.Path, "要检查的近期文件修改路径 (逗号分隔)")
	suidDirs := flag.String("suid-dirs", cfg.SuidDirs, "要扫描SUID/SGID文件的目录 (逗号分隔)")
	hemaPath := flag.String("hema-path", cfg.HemaPath, "河马工具的可执行文件路径")
	hemaResultPath := flag.String("hema-result-path", cfg.HemaResultPath, "河马工具扫描结果的输出路径")
	rulesDir := flag.String("rules-dir", cfg.RulesDir, "安全检测规则文件所在的目录")
	iocPath := flag.String("ioc-path", cfg.IOCPath, "威胁情报库 (IOC) 文件路径")
	historyFilenames := flag.String("history-filenames", strings.Join(cfg.HistoryFilenames, ","), "要检查的命令历史文件名列表 (逗号分隔)")
	tempDirs := flag.String("temp-dirs", strings.Join(cfg.TempDirs, ","), "要检查的临时目录列表 (逗号分隔)")
	flag.Parse()

	// 3. 规则验证模式
	if *validateRules {
		if !validation.ValidateRules(*rulesDir, *iocPath) {
			os.Exit(1)
		}
		os.Exit(0)
	}

	// 4. 应用内存限制
	if *memLimitMB > 0 {
		debug.SetMemoryLimit(*memLimitMB * 1024 * 1024)
		fmt.Printf("已设置内存使用限制为: %d MB\n", *memLimitMB)
	}

	// 5. 初始化规则引擎
	fmt.Println("Loading rules and IOCs...")
	ruleEngine, err := rules.NewRuleEngine(*rulesDir, *iocPath)
	if err != nil {
		fmt.Printf("严重错误: 规则引擎初始化失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Rules and IOCs loaded successfully.")

	// 6. 初始化报告数据
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

	// 7. 使用最终配置来初始化检查项
	checksToRun := []core.Checker{
		checks.RootAccountsCheck{RuleEngine: ruleEngine},
		checks.EmptyPasswordAccountsCheck{RuleEngine: ruleEngine},
		checks.SudoersCheck{RuleEngine: ruleEngine},
		checks.LastLoginsCheck{RuleEngine: ruleEngine, Limit: *loginLimit},
		checks.FailedLoginsCheck{RuleEngine: ruleEngine},
		checks.HistoryCheck{RuleEngine: ruleEngine, Filenames: strings.Split(*historyFilenames, ",")},
		checks.SuspiciousProcessesCheck{RuleEngine: ruleEngine},
		checks.DeletedRunningProcessesCheck{RuleEngine: ruleEngine},
		checks.ListeningPortsCheck{RuleEngine: ruleEngine},
		checks.EstablishedConnectionsCheck{RuleEngine: ruleEngine},
		checks.PromiscuousModeCheck{RuleEngine: ruleEngine},
		checks.SuidSgidFilesCheck{RuleEngine: ruleEngine, Dirs: strings.Split(*suidDirs, ",")},
		checks.RecentlyModifiedFilesCheck{RuleEngine: ruleEngine, Paths: strings.Split(*mtimePath, ","), Days: *mtimeDays},
		checks.TempDirsCheck{RuleEngine: ruleEngine, TempDirs: strings.Split(*tempDirs, ",")},
		checks.CronJobsCheck{RuleEngine: ruleEngine},
		checks.SystemdTimersCheck{RuleEngine: ruleEngine},
		checks.KernelModulesCheck{RuleEngine: ruleEngine},
	}
	if *webPath != "" {
		checksToRun = append(checksToRun, checks.WebshellCheck{
			RuleEngine:     ruleEngine,
			WebPath:        *webPath,
			HemaPath:       *hemaPath,
			HemaResultPath: *hemaResultPath,
		})
	}

	// 8. 并发执行所有检查并填充元数据
	fmt.Println("\n--- Starting Checks ---")
	var allResults []types.CheckResult
	var wg sync.WaitGroup
	resultsChan := make(chan []types.CheckResult, len(checksToRun))
	var completedChecks int32
	totalChecks := len(checksToRun)

	for _, chk := range checksToRun {
		wg.Add(1)
		go func(c core.Checker) {
			defer wg.Done()

			results := c.Execute()
			checkName := c.Name()

			// 为结果填充元数据
			if meta, ok := cfg.CheckTexts[checkName]; ok {
				for i := range results {
					// 如果检查项本身没有设置Description，则使用配置文件的
					if results[i].Description == "" {
						results[i].Description = meta.Description
					}
					results[i].Explanation = meta.Explanation
				}
			}

			resultsChan <- results

			// 更新进度
			atomic.AddInt32(&completedChecks, 1)
			currentCount := atomic.LoadInt32(&completedChecks)
			percent := (float64(currentCount) / float64(totalChecks)) * 100

			desc := checkName
			if meta, ok := cfg.CheckTexts[checkName]; ok {
				desc = meta.Description
			}
			fmt.Printf("✔ [%d/%d] (%.0f%%) Completed: %s\n", currentCount, totalChecks, percent, desc)
		}(chk)
	}

	wg.Wait()
	close(resultsChan)

	for res := range resultsChan {
		allResults = append(allResults, res...)
	}
	fmt.Println("--- All Checks Completed ---")

	if *webPath == "" {
		allResults = append(allResults, types.CheckResult{
			Category:    "🌐 Web安全",
			Description: "Webshell 检测",
			Result:      "[跳过]",
			Explanation: "通过 `-webpath` 参数可以指定Web目录，以启用此项检查。",
			Details:     "未提供 -webpath 参数，已跳过 Webshell 检测。",
		})
	}

	// 9. 统计结果
	reportData.Checks = allResults
	reportData.TotalChecks = len(allResults)
	var suspiciousCount int
	for _, check := range allResults {
		if check.IsSuspicious {
			suspiciousCount++
		}
	}
	reportData.SuspiciousCount = suspiciousCount

	// 10. 根据参数选择报告生成器并生成报告
	var reportGenerator report.Generator
	switch *outputFormat {
	case "json":
		reportGenerator = report.JsonGenerator{}
	case "md":
		fallthrough
	default:
		reportGenerator = report.MarkdownGenerator{}
	}

	fmt.Println("\nScan complete. Generating report...")
	err = reportGenerator.Generate(reportData, *reportOutputDir)
	if err != nil {
		fmt.Printf("错误: 生成报告失败: %v\n", err)
	}
}
