package config

import (
	"errors"
	"fmt"
	"os"
	"regexp"

	"gopkg.in/yaml.v3"
)

var envVarPattern = regexp.MustCompile(`\$\{([^}]+)\}`)

// KnowledgeEntry はナレッジベースの1エントリ
type KnowledgeEntry struct {
	Name string `yaml:"name"`
	Path string `yaml:"path"`
}

// ReconConfig は偵察ツリーの動作設定
type ReconConfig struct {
	MaxParallel int `yaml:"max_parallel"`
}

// AppConfig は config/config.yaml の統合設定構造
type AppConfig struct {
	Knowledge []KnowledgeEntry `yaml:"knowledge"`
	Blacklist []string         `yaml:"blacklist"`
	Recon     ReconConfig      `yaml:"recon"`
}

// applyDefaults はゼロ値のフィールドにデフォルト値を適用する
func (c *AppConfig) applyDefaults() {
	if c.Recon.MaxParallel == 0 {
		c.Recon.MaxParallel = 2
	}
}

// Load は config/config.yaml を読み込む。
// ${VAR} 環境変数を展開する。
// ファイルが存在しない場合はデフォルト（空）の AppConfig を返す。
func Load(path string) (*AppConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			cfg := &AppConfig{}
			cfg.applyDefaults()
			return cfg, nil
		}
		return nil, fmt.Errorf("config: failed to read %s: %w", path, err)
	}

	var cfg AppConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("config: failed to parse %s: %w", path, err)
	}

	// 環境変数を展開（knowledge path の ${VAR}）
	for i := range cfg.Knowledge {
		cfg.Knowledge[i].Path = expandEnvString(cfg.Knowledge[i].Path)
	}

	// デフォルト値の適用
	cfg.applyDefaults()

	return &cfg, nil
}

// expandEnvString は文字列内の ${VAR} をホスト環境変数で展開する
func expandEnvString(s string) string {
	return envVarPattern.ReplaceAllStringFunc(s, func(match string) string {
		varName := match[2 : len(match)-1]
		return os.Getenv(varName)
	})
}
