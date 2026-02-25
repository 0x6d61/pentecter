package brain

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

// OpenRouterModel is the minimal model metadata used by /model command.
type OpenRouterModel struct {
	ID   string
	Name string
}

type openRouterModelsResponse struct {
	Data []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"data"`
}

// FetchOpenRouterModels fetches available models from OpenRouter API.
func FetchOpenRouterModels(ctx context.Context) ([]OpenRouterModel, error) {
	cfg, err := LoadConfig(ConfigHint{Provider: ProviderOpenRouter})
	if err != nil {
		return nil, err
	}

	base := ensureV1Path(cfg.BaseURL)
	url := strings.TrimRight(base, "/") + "/models"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("openrouter: create models request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("openrouter: request models: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("openrouter: models API error %d", resp.StatusCode)
	}

	var payload openRouterModelsResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("openrouter: decode models response: %w", err)
	}

	models := make([]OpenRouterModel, 0, len(payload.Data))
	seen := make(map[string]struct{}, len(payload.Data))
	for _, m := range payload.Data {
		id := strings.TrimSpace(m.ID)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		models = append(models, OpenRouterModel{
			ID:   id,
			Name: strings.TrimSpace(m.Name),
		})
	}

	sort.Slice(models, func(i, j int) bool {
		return strings.ToLower(models[i].ID) < strings.ToLower(models[j].ID)
	})

	return models, nil
}
