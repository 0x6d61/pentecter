package brain_test

import (
	"context"
	"testing"

	"github.com/0x6d61/pentecter/internal/brain"
)

func TestLoadConfig_OpenRouter_Defaults(t *testing.T) {
	t.Setenv("OPENROUTER_API_KEY", "sk-or-test")
	t.Setenv("OPENROUTER_BASE_URL", "")
	t.Setenv("OPENROUTER_MODEL", "")

	cfg, err := brain.LoadConfig(brain.ConfigHint{
		Provider: brain.ProviderOpenRouter,
	})
	if err != nil {
		t.Fatalf("LoadConfig openrouter: %v", err)
	}
	if cfg.Token != "sk-or-test" {
		t.Errorf("Token: got %q, want sk-or-test", cfg.Token)
	}
	if cfg.AuthType != brain.AuthAPIKey {
		t.Errorf("AuthType: got %q, want %q", cfg.AuthType, brain.AuthAPIKey)
	}
	if cfg.BaseURL != "https://openrouter.ai/api/v1" {
		t.Errorf("BaseURL: got %q, want https://openrouter.ai/api/v1", cfg.BaseURL)
	}
	if cfg.Model != "openai/gpt-4o-mini" {
		t.Errorf("Model: got %q, want openai/gpt-4o-mini", cfg.Model)
	}
}

func TestOpenRouterBrain_Think(t *testing.T) {
	action := `{"thought":"test","action":"wait","seconds":1}`
	srv := mockOpenAIServer(t, openAIResponse(action))
	t.Cleanup(srv.Close)

	b, err := brain.New(brain.Config{
		Provider: brain.ProviderOpenRouter,
		Model:    "openai/gpt-4o-mini",
		Token:    "sk-or-test",
		BaseURL:  srv.URL + "/v1",
	})
	if err != nil {
		t.Fatalf("brain.New (openrouter): %v", err)
	}
	if b.Provider() != "openrouter" {
		t.Errorf("Provider(): got %q, want openrouter", b.Provider())
	}

	got, err := b.Think(context.Background(), brain.Input{})
	if err != nil {
		t.Fatalf("Think (openrouter): %v", err)
	}
	if got == nil || got.Action != "wait" {
		t.Fatalf("Think action: got %#v, want action=wait", got)
	}
}
