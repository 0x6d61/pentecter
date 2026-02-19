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
	defaultOpenAIBaseURL    = "https://api.openai.com"
	openAIChatCompletePath  = "/v1/chat/completions"
)

type openAIBrain struct {
	cfg    Config
	client *http.Client
}

func newOpenAIBrain(cfg Config) (*openAIBrain, error) {
	return &openAIBrain{
		cfg:    cfg,
		client: &http.Client{Timeout: 120 * time.Second},
	}, nil
}

func (b *openAIBrain) Provider() string { return string(ProviderOpenAI) }

func (b *openAIBrain) Think(ctx context.Context, input Input) (*schema.Action, error) {
	prompt := buildPrompt(input)

	body := map[string]any{
		"model": b.cfg.Model,
		"messages": []map[string]string{
			{"role": "system", "content": buildSystemPrompt(b.cfg.ToolNames, b.cfg.MCPTools, b.cfg.IsSubAgent)},
			{"role": "user", "content": prompt},
		},
		"max_tokens":  1024,
		"temperature": 0.2,
	}

	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("openai: marshal request: %w", err)
	}

	baseURL := b.cfg.BaseURL
	if baseURL == "" {
		baseURL = defaultOpenAIBaseURL
	}
	// BaseURL が既に /v1 で終わっている場合は /chat/completions のみ付加
	// Ollama: http://server:11434/v1 → http://server:11434/v1/chat/completions
	base := strings.TrimRight(baseURL, "/")
	var url string
	if strings.HasSuffix(base, "/v1") {
		url = base + "/chat/completions"
	} else {
		url = base + openAIChatCompletePath
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("openai: create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+b.cfg.Token)

	resp, err := b.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("openai: send request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("openai: read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("openai: API error %d: %s", resp.StatusCode, string(respBytes))
	}

	return parseOpenAIResponse(respBytes)
}

// openAIResponse は Chat Completions API のレスポンス構造体（必要最小限）。
type openAIResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
}

func parseOpenAIResponse(data []byte) (*schema.Action, error) {
	var resp openAIResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("openai: unmarshal response: %w", err)
	}

	if len(resp.Choices) == 0 {
		return nil, fmt.Errorf("openai: empty choices in response")
	}

	action, err := parseActionJSON(resp.Choices[0].Message.Content)
	if err != nil {
		return nil, fmt.Errorf("openai: parse action: %w", err)
	}
	return action, nil
}
