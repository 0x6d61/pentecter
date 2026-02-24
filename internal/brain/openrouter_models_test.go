package brain_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/0x6d61/pentecter/internal/brain"
)

func TestFetchOpenRouterModels(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Path; got != "/v1/models" {
			http.Error(w, "bad path", http.StatusNotFound)
			return
		}
		if r.Header.Get("Authorization") == "" {
			http.Error(w, "missing auth", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"data": [
				{"id": "openai/gpt-4o-mini", "name": "GPT-4o Mini"},
				{"id": "anthropic/claude-3.5-sonnet", "name": "Claude 3.5 Sonnet"},
				{"id": "openai/gpt-4o-mini", "name": "dup"}
			]
		}`))
	}))
	t.Cleanup(srv.Close)

	t.Setenv("OPENROUTER_API_KEY", "sk-or-test")
	t.Setenv("OPENROUTER_BASE_URL", srv.URL+"/v1")

	models, err := brain.FetchOpenRouterModels(context.Background())
	if err != nil {
		t.Fatalf("FetchOpenRouterModels: %v", err)
	}
	if len(models) != 2 {
		t.Fatalf("expected 2 unique models, got %d", len(models))
	}
	if models[0].ID != "anthropic/claude-3.5-sonnet" {
		t.Fatalf("expected sorted models, first=%q", models[0].ID)
	}
}
