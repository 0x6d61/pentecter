// Package brain は LLM クライアントを共通インターフェースで抽象化する。
// Anthropic（API キー）、OpenAI、Ollama をサポートする。
package brain

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/0x6d61/pentecter/pkg/schema"
)

// Provider は LLM プロバイダーを識別する。
type Provider string

const (
	ProviderAnthropic Provider = "anthropic"
	ProviderOpenAI    Provider = "openai"
	// ProviderOllama は OpenAI 互換 API 経由でローカル/リモートの Ollama サーバーに接続する。
	// API キー不要。OLLAMA_BASE_URL でサーバーを指定する（デフォルト: http://localhost:11434）。
	ProviderOllama Provider = "ollama"
)

// AuthType は認証方式を識別する。
type AuthType string

const (
	// AuthAPIKey は通常の API キー認証（Authorization: Bearer または x-api-key ヘッダー）。
	AuthAPIKey AuthType = "api_key"

	// AuthOAuthToken は Claude Code の OAuth トークン認証（Authorization: Bearer ヘッダー）。
	// `claude auth token` で取得した sk-ant-ocp01-... 形式。
	AuthOAuthToken AuthType = "oauth_token"

	// AuthNone は認証不要（Ollama 等のローカルサーバー向け）。
	AuthNone AuthType = "none"
)

// MCPToolInfo は Brain のシステムプロンプトに注入する MCP ツール情報。
// internal/mcp パッケージに依存しないよう、Brain パッケージ独自の型として定義。
type MCPToolInfo struct {
	Server      string
	Name        string
	Description string
	InputSchema map[string]any
}

// Config は Brain の設定を保持する。
type Config struct {
	Provider  Provider
	Model     string
	AuthType  AuthType
	Token     string
	BaseURL   string   // テスト時にモックサーバーを指定するために使う（空なら公式エンドポイント）
	ToolNames []string // Registry から読み込んだ登録済みツール名（システムプロンプトに注入）
	// MCPTools は MCP サーバーから取得したツールスキーマ（システムプロンプトに注入）。
	MCPTools []MCPToolInfo
	// IsSubAgent が true の場合、SubAgent 用のシステムプロンプトを使用する。
	// SubAgent は spawn_task / wait / check_task / kill_task を使わない。
	IsSubAgent bool
}

// Input は Brain に渡す思考コンテキスト。
type Input struct {
	// TargetSnapshot はターゲットの現在状態（JSON）。
	TargetSnapshot string
	// ToolOutput は直前のツール実行結果（切り捨て済み）。空でも可。
	ToolOutput string
	// LastCommand は直前に実行したコマンド (e.g. "nmap -sV 10.0.0.5")。空でも可。
	LastCommand string
	// LastExitCode は直前のコマンドの exit code (0 = success)。
	LastExitCode int
	// CommandHistory は直近N件のコマンド履歴の要約テキスト。空でも可。
	CommandHistory string
	// UserMessage はユーザーからの自然言語指示（チャット入力）。空でも可。
	UserMessage string
	// TurnCount は現在のターン番号（1始まり）。自律ループの進行度を Brain に伝える。
	TurnCount int
	// Memory は対象ホストの過去の発見物テキスト。空でも可。
	Memory string
}

// Brain は LLM との対話インターフェース。
type Brain interface {
	Think(ctx context.Context, input Input) (*schema.Action, error)
	Provider() string
}

// New は Config に基づいて適切な Brain 実装を返す。
func New(cfg Config) (Brain, error) {
	switch cfg.Provider {
	case ProviderAnthropic:
		if cfg.Token == "" {
			return nil, errors.New("brain: Anthropic token is required")
		}
		return newAnthropicBrain(cfg)

	case ProviderOpenAI:
		if cfg.Token == "" {
			return nil, errors.New("brain: OpenAI API key is required")
		}
		return newOpenAIBrain(cfg)

	case ProviderOllama:
		// Ollama は認証不要。Token が空でも動く。
		if cfg.Token == "" {
			cfg.Token = "ollama" // ダミートークン（Ollama は無視する）
		}
		if cfg.BaseURL == "" {
			cfg.BaseURL = "http://localhost:11434"
		}
		cfg.BaseURL = ensureV1Path(cfg.BaseURL)
		return newOllamaBrain(cfg) // 変更に強い薄いラッパー経由で実行

	default:
		return nil, fmt.Errorf("brain: unknown provider %q (supported: anthropic, openai, ollama)", cfg.Provider)
	}
}

// ensureV1Path は BaseURL に /v1 パスが含まれていない場合に追加する。
func ensureV1Path(baseURL string) string {
	if len(baseURL) > 3 && baseURL[len(baseURL)-3:] == "/v1" {
		return baseURL
	}
	// 末尾のスラッシュを除去してから /v1 を追加
	for len(baseURL) > 0 && baseURL[len(baseURL)-1] == '/' {
		baseURL = baseURL[:len(baseURL)-1]
	}
	return baseURL + "/v1"
}

// DetectAvailableProviders は環境変数を調べ、利用可能なプロバイダーを優先順に返す。
// 優先順位: Anthropic > OpenAI > Ollama
// Ollama は OLLAMA_BASE_URL が明示的に設定されている場合のみ検出する（localhost への疎通チェックは行わない）。
func DetectAvailableProviders() []Provider {
	var providers []Provider

	// Anthropic: API key or OAuth token
	if os.Getenv("ANTHROPIC_API_KEY") != "" ||
		os.Getenv("CLAUDE_CODE_OAUTH_TOKEN") != "" ||
		os.Getenv("ANTHROPIC_AUTH_TOKEN") != "" {
		providers = append(providers, ProviderAnthropic)
	}

	// OpenAI
	if os.Getenv("OPENAI_API_KEY") != "" {
		providers = append(providers, ProviderOpenAI)
	}

	// Ollama: only if OLLAMA_BASE_URL is explicitly set
	if os.Getenv("OLLAMA_BASE_URL") != "" {
		providers = append(providers, ProviderOllama)
	}

	return providers
}

// ConfigHint は LoadConfig へのヒントを保持する。認証情報は環境変数から自動解決する。
type ConfigHint struct {
	Provider Provider
	Model    string
	BaseURL  string
}

// LoadConfig は環境変数から認証情報を解決して Config を返す。
//
// Anthropic 優先順位:
//  1. ANTHROPIC_API_KEY       → AuthAPIKey
//  2. ANTHROPIC_AUTH_TOKEN    → AuthOAuthToken（`claude auth token` の出力）
//
// OpenAI:
//  1. OPENAI_API_KEY          → AuthAPIKey
//
// Ollama:
//  1. OLLAMA_BASE_URL         → サーバー URL（デフォルト: http://localhost:11434）
//  2. 認証不要
func LoadConfig(hint ConfigHint) (Config, error) {
	cfg := Config{
		Provider: hint.Provider,
		Model:    hint.Model,
		BaseURL:  hint.BaseURL,
	}

	switch hint.Provider {
	case ProviderAnthropic:
		if cfg.Model == "" {
			cfg.Model = "claude-sonnet-4-6"
		}
		if key := os.Getenv("ANTHROPIC_API_KEY"); key != "" {
			cfg.Token = key
			cfg.AuthType = AuthAPIKey
			return cfg, nil
		}
		// Claude Code OAuth token: CLAUDE_CODE_OAUTH_TOKEN (公式) or ANTHROPIC_AUTH_TOKEN (互換)
		for _, envKey := range []string{"CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_AUTH_TOKEN"} {
			if token := os.Getenv(envKey); token != "" {
				cfg.Token = token
				cfg.AuthType = AuthOAuthToken
				return cfg, nil
			}
		}
		return cfg, errors.New(
			"brain: Anthropic credentials not found, set ANTHROPIC_API_KEY or CLAUDE_CODE_OAUTH_TOKEN",
		)

	case ProviderOpenAI:
		if key := os.Getenv("OPENAI_API_KEY"); key != "" {
			cfg.Token = key
			cfg.AuthType = AuthAPIKey
			return cfg, nil
		}
		return cfg, errors.New(
			"brain: OpenAI credentials not found, set OPENAI_API_KEY",
		)

	case ProviderOllama:
		// BaseURL が hint で指定されていなければ環境変数から読む
		if cfg.BaseURL == "" {
			cfg.BaseURL = os.Getenv("OLLAMA_BASE_URL")
		}
		if cfg.BaseURL == "" {
			cfg.BaseURL = "http://localhost:11434"
		}
		// モデルが指定されていなければ環境変数から読む
		if cfg.Model == "" {
			cfg.Model = os.Getenv("OLLAMA_MODEL")
		}
		if cfg.Model == "" {
			cfg.Model = "llama3.2"
		}
		cfg.Token = "ollama"
		cfg.AuthType = AuthNone
		return cfg, nil

	default:
		return cfg, fmt.Errorf("brain: unknown provider %q", hint.Provider)
	}
}
