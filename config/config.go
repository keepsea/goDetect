// FILE: config/config.go
package config

import (
	"io/ioutil"

	"gopkg.in/yaml.v3"
)

// Config 结构体定义了所有可配置的参数
type Config struct {
	Output     string `yaml:"output"`
	MemLimitMB int64  `yaml:"mem_limit_mb"`
	WebPath    string `yaml:"webpath"`
	LoginLimit int    `yaml:"login_limit"`
	Mtime      struct {
		Path string `yaml:"path"`
		Days int    `yaml:"days"`
	} `yaml:"mtime"`
	SuidDirs         string   `yaml:"suid_dirs"`
	HemaPath         string   `yaml:"hema_path"`
	HemaResultPath   string   `yaml:"hema_result_path"`
	RulesDir         string   `yaml:"rules_dir"`
	IOCPath          string   `yaml:"ioc_path"`
	HistoryFilenames []string `yaml:"history_filenames"`
	TempDirs         []string `yaml:"temp_dirs"`
}

// LoadConfig 加载并解析配置文件
// 它会依次尝试 ./config.yaml 和 /etc/goDetect/config.yaml
func LoadConfig() (*Config, error) {
	// 设置默认值
	cfg := &Config{
		Output:     "md",
		MemLimitMB: 0,
		WebPath:    "",
		LoginLimit: 50,
		Mtime: struct {
			Path string `yaml:"path"`
			Days int    `yaml:"days"`
		}{Path: "/etc", Days: 7},
		SuidDirs:         "/",
		HemaPath:         "./hm",
		HemaResultPath:   "./result.csv",
		RulesDir:         "./rules",
		IOCPath:          "./ioc.yaml",
		HistoryFilenames: []string{".bash_history", ".zsh_history", ".history"},
		TempDirs:         []string{"/tmp", "/var/tmp"},
	}

	configPaths := []string{"./config.yaml", "/etc/goDetect/config.yaml"}
	var err error
	var yamlFile []byte

	for _, path := range configPaths {
		yamlFile, err = ioutil.ReadFile(path)
		if err == nil {
			break // 找到并成功读取文件
		}
	}

	if err != nil {
		// 如果所有路径都找不到文件，这不是一个错误，程序将使用默认值
		return cfg, nil
	}

	err = yaml.Unmarshal(yamlFile, cfg)
	if err != nil {
		return nil, err
	}

	return cfg, nil
}
