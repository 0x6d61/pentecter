// Package brain は LLM クライアントを共通インターフェースで抽象化する。
// Anthropic（claude auth token / API キー）と OpenAI の両方をサポートする。
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
)

// AuthType は認証方式を識別する。
type AuthType string

const (
	// AuthAPIKey は通常の API キー認証（x-api-key ヘッダー）。
	// console.anthropic.com で発行した sk-ant-api03-... 形式。
	AuthAPIKey AuthType = "api_key"

	// AuthOAuthToken は Claude Code の OAuth トークン認証（Authorization: Bearer ヘッダー）。
	// `claude auth token` で取得した sk-ant-ocp01-... 形式。
	AuthOAuthToken AuthType = "oauth_token"
)

// Config は Brain の設定を保持する。
type Config struct {
	Provider Provider
	Model    string
	AuthType AuthType
	Token    string
	BaseURL  string // テスト時にモックサーバーを指定するために使う（空なら公式エンドポイント）
}

// Input は Brain に渡す思考コンテキスト。
type Input struct {
	// TargetSnapshot はターゲットの現在状態（JSON）。Entity抽出済みの構造体。
	TargetSnapshot string
	// ToolOutput は直前のツール実行結果（切り捨て済み）。空でも可。
	ToolOutput string
	// UserMessage はユーザーからの自然言語指示（チャット入力）。空でも可。
	UserMessage string
}

// Brain は LLM との対話インターフェース。
type Brain interface {
	// Think はコンテキストを LLM に渡し、次のアクションを返す。
	Think(ctx context.Context, input Input) (*schema.Action, error)
	// Provider はプロバイダー名を返す。
	Provider() string
}

// New は Config に基づいて適切な Brain 実装を返す。
func New(cfg Config) (Brain, error) {
	if cfg.Token == "" {
		return nil, errors.New("brain: token must not be empty (set ANTHROPIC_API_KEY or run `claude auth token`)")
	}

	switch cfg.Provider {
	case ProviderAnthropic:
		return newAnthropicBrain(cfg)
	case ProviderOpenAI:
		return newOpenAIBrain(cfg)
	default:
		return nil, fmt.Errorf("brain: unknown provider %q (supported: anthropic, openai)", cfg.Provider)
	}
}

// ConfigHint は LoadConfig へのヒント（プロバイダー・モデル）を保持する。
// 認証情報は環境変数から自動解決する。
type ConfigHint struct {
	Provider Provider
	Model    string
	BaseURL  string
}

// LoadConfig は環境変数から認証情報を解決して Config を返す。
//
// 解決優先順位（Anthropic）:
//  1. ANTHROPIC_API_KEY       → AuthAPIKey
//  2. ANTHROPIC_AUTH_TOKEN    → AuthOAuthToken（`claude auth token` の出力）
//
// 解決優先順位（OpenAI）:
//  1. OPENAI_API_KEY          → AuthAPIKey
func LoadConfig(hint ConfigHint) (Config, error) {
	cfg := Config{
		Provider: hint.Provider,
		Model:    hint.Model,
		BaseURL:  hint.BaseURL,
	}

	switch hint.Provider {
	case ProviderAnthropic:
		if key := os.Getenv("ANTHROPIC_API_KEY"); key != "" {
			cfg.Token = key
			cfg.AuthType = AuthAPIKey
			return cfg, nil
		}
		if token := os.Getenv("ANTHROPIC_AUTH_TOKEN"); token != "" {
			cfg.Token = token
			cfg.AuthType = AuthOAuthToken
			return cfg, nil
		}
		return cfg, errors.New(
			"brain: Anthropic 認証情報が見つかりません\n" +
				"  - API キー:        export ANTHROPIC_API_KEY=sk-ant-api03-...\n" +
				"  - Claude Code 認証: export ANTHROPIC_AUTH_TOKEN=$(claude auth token)",
		)

	case ProviderOpenAI:
		if key := os.Getenv("OPENAI_API_KEY"); key != "" {
			cfg.Token = key
			cfg.AuthType = AuthAPIKey
			return cfg, nil
		}
		return cfg, errors.New(
			"brain: OpenAI 認証情報が見つかりません\n" +
				"  export OPENAI_API_KEY=sk-...",
		)

	default:
		return cfg, fmt.Errorf("brain: unknown provider %q", hint.Provider)
	}
}
