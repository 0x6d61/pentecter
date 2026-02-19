package mcp

import (
	"errors"
	"fmt"
	"os"
	"regexp"

	"gopkg.in/yaml.v3"
)

// envVarPattern は ${VAR_NAME} 形式の環境変数参照にマッチする正規表現
var envVarPattern = regexp.MustCompile(`\$\{([^}]+)\}`)

// LoadConfig は指定パスから MCP 設定ファイルを読み込む。
// ファイルが存在しない場合は nil, nil を返す（graceful skip）。
// env フィールドの値に含まれる ${VAR} はホスト環境変数から展開される。
func LoadConfig(path string) (*MCPConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("mcp: failed to read config %s: %w", path, err)
	}

	var cfg MCPConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("mcp: failed to parse config %s: %w", path, err)
	}

	// 環境変数を展開（env, args, command の ${VAR} を展開）
	for i := range cfg.Servers {
		expandEnvVars(cfg.Servers[i].Env)
		cfg.Servers[i].Command = expandEnvString(cfg.Servers[i].Command)
		for j := range cfg.Servers[i].Args {
			cfg.Servers[i].Args[j] = expandEnvString(cfg.Servers[i].Args[j])
		}
	}

	return &cfg, nil
}

// expandEnvString は文字列内の ${VAR} をホスト環境変数で展開する
func expandEnvString(s string) string {
	return envVarPattern.ReplaceAllStringFunc(s, func(match string) string {
		varName := match[2 : len(match)-1]
		return os.Getenv(varName)
	})
}

// expandEnvVars は map 内の値に含まれる ${VAR} をホスト環境変数で展開する
func expandEnvVars(env map[string]string) {
	for k, v := range env {
		env[k] = expandEnvString(v)
	}
}
