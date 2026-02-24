package brain

import (
	"context"

	"github.com/0x6d61/pentecter/pkg/schema"
)

// openRouterBrain は OpenRouter の OpenAI 互換 API を使う Brain 実装。
type openRouterBrain struct {
	inner *openAIBrain
}

func newOpenRouterBrain(cfg Config) (*openRouterBrain, error) {
	inner, err := newOpenAIBrain(cfg)
	if err != nil {
		return nil, err
	}
	return &openRouterBrain{inner: inner}, nil
}

// Provider はプロバイダー名を返す。
func (b *openRouterBrain) Provider() string { return string(ProviderOpenRouter) }

// Think は OpenRouter に思考させる。OpenAI 互換 API 経由で委譲する。
func (b *openRouterBrain) Think(ctx context.Context, input Input) (*schema.Action, error) {
	return b.inner.Think(ctx, input)
}

// ExtractTarget はユーザーテキストからターゲットホストを抽出する。
func (b *openRouterBrain) ExtractTarget(ctx context.Context, userText string) (string, string, error) {
	return b.inner.ExtractTarget(ctx, userText)
}
