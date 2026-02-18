package brain

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/0x6d61/pentecter/pkg/schema"
)

const (
	defaultAnthropicBaseURL = "https://api.anthropic.com"
	anthropicMessagesPath   = "/v1/messages"
	anthropicVersion        = "2023-06-01"
)

type anthropicBrain struct {
	cfg    Config
	client *http.Client
}

func newAnthropicBrain(cfg Config) (*anthropicBrain, error) {
	return &anthropicBrain{
		cfg:    cfg,
		client: &http.Client{Timeout: 120 * time.Second},
	}, nil
}

func (b *anthropicBrain) Provider() string { return string(ProviderAnthropic) }

func (b *anthropicBrain) Think(ctx context.Context, input Input) (*schema.Action, error) {
	prompt := buildPrompt(input)

	body := map[string]any{
		"model":      b.cfg.Model,
		"max_tokens": 1024,
		"system":     systemPrompt,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
	}

	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("anthropic: marshal request: %w", err)
	}

	baseURL := b.cfg.BaseURL
	if baseURL == "" {
		baseURL = defaultAnthropicBaseURL
	}
	url := strings.TrimRight(baseURL, "/") + anthropicMessagesPath

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("anthropic: create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("anthropic-version", anthropicVersion)

	// 認証方式に応じてヘッダーを設定する。
	// AuthAPIKey    → x-api-key ヘッダー（標準 API キー）
	// AuthOAuthToken → Authorization: Bearer + OAuth 必須ヘッダー（claude setup-token の出力）
	switch b.cfg.AuthType {
	case AuthOAuthToken:
		req.Header.Set("Authorization", "Bearer "+b.cfg.Token)
		req.Header.Set("anthropic-beta", "oauth-2025-04-20")
		req.Header.Set("anthropic-dangerous-direct-browser-access", "true")
	default:
		req.Header.Set("x-api-key", b.cfg.Token)
	}

	resp, err := b.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("anthropic: send request: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("anthropic: read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("anthropic: API error %d: %s", resp.StatusCode, string(respBytes))
	}

	return parseAnthropicResponse(respBytes)
}

// anthropicResponse は Anthropic Messages API のレスポンス構造体（必要最小限）。
type anthropicResponse struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
}

func parseAnthropicResponse(data []byte) (*schema.Action, error) {
	var resp anthropicResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("anthropic: unmarshal response: %w", err)
	}

	for _, block := range resp.Content {
		if block.Type != "text" {
			continue
		}
		action, err := parseActionJSON(block.Text)
		if err != nil {
			return nil, fmt.Errorf("anthropic: parse action: %w", err)
		}
		return action, nil
	}

	return nil, fmt.Errorf("anthropic: no text content in response")
}
