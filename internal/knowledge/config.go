package knowledge

import (
	"errors"
	"fmt"
	"os"
	"regexp"

	"gopkg.in/yaml.v3"
)

// envVarPattern は ${VAR_NAME} 形式の環境変数参照にマッチする正規表現
var envVarPattern = regexp.MustCompile(`\$\{([^}]+)\}`)

// KnowledgeConfig は knowledge.yaml の構造
type KnowledgeConfig struct {
	Knowledge []KnowledgeEntry `yaml:"knowledge"`
}

// KnowledgeEntry はナレッジベースの1エントリ
type KnowledgeEntry struct {
	Name string `yaml:"name"`
	Path string `yaml:"path"`
}

// LoadConfig は config/knowledge.yaml を読み込む。
// ${VAR} 環境変数を展開する（既存の expandEnvString パターンを参考に）。
// ファイルが存在しない場合は nil, nil を返す（graceful skip）。
func LoadConfig(path string) (*KnowledgeConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("knowledge: failed to read config %s: %w", path, err)
	}

	var cfg KnowledgeConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("knowledge: failed to parse config %s: %w", path, err)
	}

	// 環境変数を展開（path の ${VAR} を展開）
	for i := range cfg.Knowledge {
		cfg.Knowledge[i].Path = expandEnvString(cfg.Knowledge[i].Path)
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
