

---

      ,---------------------------,
     |  /---------------------\  |
     | |                       | |
     | |       /\_ /\\        | |
     | |      ( o.o )       | |
     | |       > ^ <        | |
     | |                       | |
     |  \_____________________/  |
     |___________________________|
   ,---\_____     []     _______/--,
  /         `------------------'    \
  \___________________________________/


---

## 1. 工具简介

**goDetect** 是一款专为Linux系统（尤其是麒麟操作系统）设计的轻量级、高性能的主机失陷检测工具。它通过执行一系列安全检查，并结合可灵活配置的**规则引擎**和**威胁情报库**，帮助安全分析师和系统管理员快速发现主机上的潜在异常和安全威胁。


## 2. 版本选择

两个版本，请根据服务器环境和检测需求选择合适的版本：

| 程序名称 | 功能 | 依赖 | 推荐使用场景 |
| :--- | :--- | :--- | :--- |
| `goDetect_yara` | **完整版** | **需要**在服务器上预先安装YARA库 | 适用于可以安装依赖、需要进行深度文件恶意代码扫描的安全分析环境。 |
| `goDetect_no_yara`| **通用版** | **无需**任何额外依赖 | 适用于无法安装YARA、或只需要进行主机配置及日志基线检查的生产服务器。 |

## 3. 部署与准备

要成功运行goDetect，请在目标服务器上完成以下部署步骤。

### 3.1. 环境依赖

* **操作系统**: 主流Linux发行版 (Kylin, Ubuntu, CentOS, Debian等)。
* **YARA库 (仅完整版需要)**:
    * **重要说明**: 如果您选择使用 `goDetect_yara`，必须在服务器上预先安装YARA。这是标准且推荐的做法，可以确保您能及时获得YARA本身的安全更新。
    * 在Debian/Ubuntu上: `sudo apt-get install -y yara libyara-dev`
    * 在CentOS/RHEL上: `sudo yum install -y yara`
    * 在macOS上: `brew install yara`
    * 如果包管理器安装失败，请参考**手动编译安装YARA指南**。
* **河马扫描器 (可选)**: 如果需要进行Webshell检测，请下载其可执行文件。

### 3.2. 部署步骤

1.  **创建主目录**: 创建一个项目主目录，例如 `/opt/goDetect/`。
2.  **上传主程序**:
    * 根据您的需求，选择 `goDetect_yara` 或 `goDetect_no_yara` 上传到 `/opt/goDetect/` 目录。
    * **建议**: 为了方便使用，可以将其重命名为 `goDetect`。
    * 为其添加执行权限：`chmod +x /opt/goDetect/goDetect`。
3.  **上传依赖工具 (可选)**:
    * 如果需要进行Webshell检测，将**河马扫描器**可执行文件也放入 `/opt/goDetect/` 目录，并重命名为 `hm`。
    * 为 `hm` 添加执行权限：`chmod +x /opt/goDetect/hm`。
4.  **创建配置文件**:
    * 在 `/opt/goDetect/` 目录下，创建一个 `config.yaml` 文件。这是主要的配置文件。
    * 在 `/opt/goDetect/` 目录下，创建一个 `ioc.yaml` 文件。这是威胁情报库。
5.  **创建规则目录**:
    * 在 `/opt/goDetect/` 目录下，创建一个 `rules` 文件夹。
    * 将所有 `.yaml` 和 `.yar` 格式的规则文件放入此目录。

最终，您在服务器上的部署结构应如下所示：
```
/opt/goDetect/
├── goDetect              # (您选择的主程序)
├── hm                    # (可选, 河马扫描器)
├── config.yaml           # (中心化配置文件)
├── ioc.yaml              # (威胁情报库)
└── rules/                # (规则目录)
    ├── account.yaml
    ├── process.yaml
    ├── malware.yar
    └── ... (其他规则文件)
```

## 4. 运行与使用

**强烈建议使用** `sudo` **运行本工具**，以确保所有检查项都有足够的权限获取系统信息。

### 4.1. 基本运行

进入部署目录，执行程序：
```bash
cd /opt/goDetect/
sudo ./goDetect
```
程序将使用 `config.yaml` 中的配置（或默认值）进行扫描。

### 4.2. 命令行参数

所有在 `config.yaml` 中的配置项都可以通过命令行参数进行**临时覆盖**。命令行参数的优先级高于配置文件。

* `-h` 或 `-help`: 显示所有可用的命令行参数及其说明。
* `-validate-rules`: **(重要)** 只验证规则文件的正确性，不执行扫描。在更新规则后，建议先执行此命令进行检查。
    * `sudo ./goDetect -validate-rules`
* `-output`: 指定报告输出格式。
    * `sudo ./goDetect -output=json`
* `-webpath`: 指定要扫描的Web目录。
    * `sudo ./goDetect -webpath=/var/www/html`
* `-suid-dirs`: 指定扫描SUID/SGID文件的目录，以提升性能。
    * `sudo ./goDetect -suid-dirs="/bin,/usr/bin,/sbin"`
* `...` (其他参数请通过 `-help` 查看)

## 5. 配置文件详解 (`config.yaml`)

`config.yaml` 是goDetect的核心配置文件，它允许您集中管理工具的行为。

```yaml
# 报告输出格式 (md, json)
output: "md"

# 内存使用限制 (MB)，0为不限制
mem_limit_mb: 0

# Webshell 扫描路径 (为空则不扫描)
webpath: ""

# 登录记录审计条数
login_limit: 100

# 近期文件修改检查配置
mtime:
  path: "/etc,/var/log" # 可以配置多个路径，用逗号分隔
  days: 14

# SUID/SGID 文件扫描目录 (用逗号分隔)
suid_dirs: "/bin,/sbin,/usr/bin,/usr/sbin"

# 河马工具的可执行文件路径
hema_path: "./hm"

# 河马工具扫描结果的输出路径
hema_result_path: "./result.csv"

# 安全检测规则文件所在的目录
rules_dir: "./rules"

# 威胁情报库 (IOC) 文件路径
ioc_path: "./ioc.yaml"

# 要检查的命令历史文件名列表
history_filenames:
  - ".bash_history"
  - ".zsh_history"

# 要检查的临时目录列表
temp_dirs:
  - "/tmp"
  - "/var/tmp"
  - "/dev/shm"
```

## 6. 规则与情报维护

goDetect的核心优势在于其可成长性。您可以通过维护 `rules/` 目录和 `ioc.yaml` 文件来持续提升其检测能力。

### 6.1. 规则文件结构

所有规则文件都必须放置在程序根目录下的 `rules/` 文件夹内，并以 `.yaml` 结尾。建议按检查项类型命名文件，例如 `cron.yaml`, `process.yaml` 等。

每个规则文件包含一个 `rules` 列表，列表中的每一项都是一条独立的检测规则。

#### 单条规则的通用字段

每条规则都由以下几个关键字段构成：

| 字段名 | 类型 | 是否必需 | 描述 |
| :--- | :--- | :--- | :--- |
| `name` | String | 是 | 规则的唯一名称，用于标识。应简明扼要，如 `History_Reverse_Shell`。|
| `enabled`| Boolean| 是 | `true` 或 `false`。用于快速启用或禁用某条规则，而无需删除。|
| `description`| String | 是 | 对这条规则作用的详细描述，会显示在最终的告警信息中。|
| `target_check`| String | 是 | 规则所应用的检查项。必须与程序中定义的检查项名称完全对应（如 `CronJobsCheck`）。|
| `type` | String | 是 | 规则的匹配类型。详见下文。|
| `patterns`| List | 否 | 匹配模式列表。用于 `keyword` 和 `regex` 类型。|
| `pattern`| String | 否 | 单一匹配模式。用于 `agg_regex` 类型。|
| `condition`| String | 否 | 聚合条件。用于 `agg_regex` 类型。|
| `risk_level`| String | 是 | 风险等级，可以是 `Low`, `Medium`, `High`, `Critical`。|

### 6.2. 规则匹配类型详解

规则引擎支持三种核心的匹配类型，以应对不同的检测场景。

#### 关键词匹配 (`type: "keyword"`)

* **使用场景**: 用于快速、高效地查找已知的、固定的字符串或命令片段。这是性能最高的匹配方式。
* **语法**: 在 `patterns` 列表中定义一个或多个需要查找的关键词。只要目标文本中**包含**列表中的任意一个关键词，即匹配成功。
* **示例**: 在命令历史中查找常见的反弹shell命令。
    ```yaml
    - name: "History_Reverse_Shell"
      enabled: true
      description: "在命令历史中检测常见的反弹shell命令。"
      target_check: "HistoryCheck"
      type: "keyword"
      patterns:
        - "nc -e /bin/sh"
        - "ncat -e /bin/bash"
        - "bash -i >& /dev/tcp/"
      risk_level: "High"
    ```

#### 正则表达式匹配 (`type: "regex"`)

* **使用场景**: 用于检测符合某种特定**行为模式**的事件，例如“下载并执行”、“解码并执行”等。功能强大但性能开销相对较高。
* **语法**: 在 `patterns` 列表中定义一个或多个正则表达式。只要目标文本能匹配列表中的任意一个正则表达式，即匹配成功。规则引擎使用Go语言标准库的RE2正则引擎。
* **注意**: 在YAML中，如果正则表达式包含反斜杠 `\`，需要进行转义，写为 `\\`。
* **示例**: 检测通过 `curl` 或 `wget` 下载脚本并通过管道直接执行的恶意定时任务。
    ```yaml
    - name: "Cronjob_Downloads_And_Executes_Script"
      enabled: true
      description: "检测直接从网络下载脚本并执行的定时任务。"
      target_check: "CronJobsCheck"
      type: "regex"
      patterns:
        - "(curl|wget).*\\|.*sh"
      risk_level: "Critical"
    ```

#### 聚合正则匹配 (`type: "agg_regex"`)

* **使用场景**: 用于检测需要进行统计分析的攻击行为，例如暴力破解。在这种场景下，单次事件无害，但大量重复的事件则构成威胁。
* **语法**:
    * `pattern`: **(必需)** 定义一个正则表达式，该表达式必须包含至少一个**捕获组**（用括号 `()` 包围），用于从多行日志中提取实体（如IP地址、用户名等）。
    * `condition`: **(必需)** 定义一个触发警报的条件。目前支持 `count`变量（表示提取到的同一实体的出现次数）和比较运算符 `>`、`<`、`==`。
* **示例**: 检测来自同一IP的SSH登录失败次数超过10次的暴力破解行为。
    ```yaml
    - name: "SSH_Brute_Force_Attack"
      enabled: true
      description: "检测来自同一IP的大量失败登录尝试。"
      target_check: "FailedLoginsCheck"
      type: "agg_regex"
      pattern: "(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})" # 捕获组( ... )用于提取IP
      condition: "count > 10" # 当同一个IP的count大于10时触发
      risk_level: "Medium"
    ```

### 6.3. 规则维护最佳实践

* **优先使用 `keyword`**: 在能满足检测需求的情况下，优先使用 `keyword` 匹配，它的性能远高于 `regex`。
* **编写清晰的 `description`**: 详细的描述能帮助其他分析人员快速理解告警的含义和背景。
* **谨慎编写 `regex`**: 不严谨的正则表达式可能会导致性能问题或大量误报。建议在工具（如 [Regex101](https://regex101.com/)）中充分测试后再加入规则文件。
* **小步快跑**: 每次只添加或修改少量规则，并进行充分测试，以验证其有效性和准确性。
* **善用 `enabled: false`**: 在调试或暂时下线某条规则时，将其设置为 `false`，而不是直接删除。

## 7. 解读检测报告

程序默认生成Markdown格式的报告，便于人工阅读。

* **报告摘要**: 提供了本次扫描的概览，您可以从“发现可疑项”快速判断主机的整体安全状况。
* **详细检测结果**:
    * **结果**: `[正常]` 或 `[可疑]`，是对该项检查的最终判定。
    * **检查说明**: 解释了该项检查的目的、方法和判断依据。
    * **规则匹配发现**: 如果规则引擎发现了风险，会在此处详细列出匹配到的规则名称、风险等级和具体内容。
    * **原始数据**: 无论结果如何，此处都提供了检查项收集到的最原始的命令行输出或文件内容，供您进行深入审计和确认。
