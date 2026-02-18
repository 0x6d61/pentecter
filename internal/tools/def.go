package tools

// ToolDef はYAMLから読み込むツール定義。
// Goコードを書かずに tools/*.yaml を追加するだけで新ツールが使える。
type ToolDef struct {
	Name        string          `yaml:"name"`
	Binary      string          `yaml:"binary"`
	Description string          `yaml:"description"`
	Tags        []string        `yaml:"tags"`
	TimeoutSec  int             `yaml:"timeout"`
	DefaultArgs []string        `yaml:"default_args"`
	Output      OutputConfig    `yaml:"output"`
}

// OutputConfig はツール出力の切り捨て設定。
type OutputConfig struct {
	Strategy  TruncateStrategy `yaml:"strategy"`
	HeadLines int              `yaml:"head_lines"`
	TailLines int              `yaml:"tail_lines"`
	BodyBytes int              `yaml:"body_bytes"`
}

// TruncateConfig に変換する。
func (o OutputConfig) ToTruncateConfig() TruncateConfig {
	cfg := TruncateConfig{Strategy: o.Strategy}
	switch o.Strategy {
	case StrategyHTTPResponse:
		cfg.BodyBytes = o.BodyBytes
		if cfg.BodyBytes == 0 {
			cfg.BodyBytes = DefaultHTTPConfig.BodyBytes
		}
	default:
		cfg.Strategy = StrategyHeadTail
		cfg.HeadLines = o.HeadLines
		cfg.TailLines = o.TailLines
		if cfg.HeadLines == 0 {
			cfg.HeadLines = DefaultHeadTailConfig.HeadLines
		}
		if cfg.TailLines == 0 {
			cfg.TailLines = DefaultHeadTailConfig.TailLines
		}
	}
	return cfg
}
