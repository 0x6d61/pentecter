package brain

import (
	"context"

	"github.com/0x6d61/pentecter/pkg/schema"
)

// openRouterBrain uses OpenRouter's OpenAI-compatible API.
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

func (b *openRouterBrain) Provider() string { return string(ProviderOpenRouter) }

func (b *openRouterBrain) Think(ctx context.Context, input Input) (*schema.Action, error) {
	return b.inner.Think(ctx, input)
}

func (b *openRouterBrain) ExtractTarget(ctx context.Context, userText string) (string, string, error) {
	return b.inner.ExtractTarget(ctx, userText)
}
