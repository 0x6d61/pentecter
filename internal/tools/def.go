package tools

// ToolDef は tools/*.yaml から読み込むツール設定。
// Brain がコマンド文字列を生成し、CommandRunner がこの設定で実行方式を決定する。
//
// name はコマンドの先頭ワード（binary 名）と一致させること。
// Brain が "nmap -sV 10.0.0.5" を生成したとき、CommandRunner は "nmap" で Registry を検索する。
type ToolDef struct {
	Name        string       `yaml:"name"`        // コマンドの先頭ワードと一致する識別子
	Description string       `yaml:"description"`
	Tags        []string     `yaml:"tags"`
	TimeoutSec  int          `yaml:"timeout"` // コンテキストタイムアウト（秒）。0 なら 300 秒
	Output      OutputConfig `yaml:"output"`

	// Docker はオプションの Docker 実行設定。
	// 設定があれば Docker コンテナ内で実行し、ホストを保護する。
	Docker *DockerConfig `yaml:"docker,omitempty"`

	// ProposalRequired は Brain が propose アクションを使うべきかを制御する。
	// nil の場合: Docker あり → false（自動実行）、なし → true（要承認）
	// 明示的に false を設定するとホスト実行でも自動承認になる（信頼済みツール向け）。
	ProposalRequired *bool `yaml:"proposal_required,omitempty"`
}

// DockerConfig はツールを Docker コンテナ内で実行するための設定。
type DockerConfig struct {
	Image    string   `yaml:"image"`              // Docker イメージ名
	Network  string   `yaml:"network"`             // ネットワークモード（デフォルト: host）
	RunFlags []string `yaml:"run_flags,omitempty"` // 追加の docker run フラグ
	Fallback bool     `yaml:"fallback"`            // Docker 不可時にホスト実行にフォールバックするか
}

// IsProposalRequired は Brain が propose アクションを使うべきかを返す。
// YAML の proposal_required が明示されていればそれに従い、
// なければ Docker 有無でデフォルトを決める。
func (d *ToolDef) IsProposalRequired() bool {
	if d.ProposalRequired != nil {
		return *d.ProposalRequired
	}
	// Docker 設定があれば自動承認（サンドボックス隔離）
	return d.Docker == nil
}

// OutputConfig はツール出力の切り捨て設定。
type OutputConfig struct {
	Strategy  TruncateStrategy `yaml:"strategy"`
	HeadLines int              `yaml:"head_lines"`
	TailLines int              `yaml:"tail_lines"`
	BodyBytes int              `yaml:"body_bytes"`
}

// ToTruncateConfig は OutputConfig を TruncateConfig に変換する。
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
