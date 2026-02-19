package brain

import (
	"context"

	"github.com/0x6d61/pentecter/pkg/schema"
)

// ollamaBrain は Ollama の OpenAI 互換 API を使う Brain 実装。
//
// 現在は openAIBrain に委譲しているが、Ollama 固有の挙動が必要になった場合は
// このファイルだけを変更すれば済む（openai.go に影響を与えない）。
//
// Ollama の OpenAI 互換 API:
//   POST <base_url>/v1/chat/completions
//   Authorization ヘッダーは無視される（認証不要）
//   https://github.com/ollama/ollama/blob/main/docs/openai.md
type ollamaBrain struct {
	inner *openAIBrain
}

func newOllamaBrain(cfg Config) (*ollamaBrain, error) {
	inner, err := newOpenAIBrain(cfg)
	if err != nil {
		return nil, err
	}
	return &ollamaBrain{inner: inner}, nil
}

// Provider はプロバイダー名を返す。
func (b *ollamaBrain) Provider() string { return string(ProviderOllama) }

// Think は Ollama に思考させる。現在は OpenAI 互換 API 経由で委譲する。
// Ollama 固有の処理（例: ストリーミング差異、カスタムオプション）が必要になったら
// このメソッドをオーバーライドする。
func (b *ollamaBrain) Think(ctx context.Context, input Input) (*schema.Action, error) {
	return b.inner.Think(ctx, input)
}

// ExtractTarget はユーザーテキストから LLM を使ってターゲットホストを抽出する。
// OpenAI 互換 API 経由で委譲する。
func (b *ollamaBrain) ExtractTarget(ctx context.Context, userText string) (string, string, error) {
	return b.inner.ExtractTarget(ctx, userText)
}
