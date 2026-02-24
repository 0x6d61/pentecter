package tui

import (
	"bytes"
	"context"
	"testing"

	"github.com/0x6d61/pentecter/internal/agent"
	"github.com/0x6d61/pentecter/internal/brain"
)

func TestExtractHostFromText(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantHost string
		wantMsg  string
		wantOK   bool
	}{
		{
			name:     "Japanese with IP",
			input:    "192.168.81.1をスキャンして",
			wantHost: "192.168.81.1",
			wantMsg:  "をスキャンして",
			wantOK:   true,
		},
		{
			name:     "English with IP",
			input:    "scan 10.0.0.5 please",
			wantHost: "10.0.0.5",
			wantMsg:  "scan please",
			wantOK:   true,
		},
		{
			name:     "IP only",
			input:    "192.168.1.1",
			wantHost: "192.168.1.1",
			wantMsg:  "",
			wantOK:   true,
		},
		{
			name:     "IP at end of text",
			input:    "please scan 172.16.0.1",
			wantHost: "172.16.0.1",
			wantMsg:  "please scan",
			wantOK:   true,
		},
		{
			name:     "no IP or domain",
			input:    "hello world",
			wantHost: "",
			wantMsg:  "",
			wantOK:   false,
		},
		{
			name:     "command prefix",
			input:    "/target 10.0.0.5",
			wantHost: "",
			wantMsg:  "",
			wantOK:   false,
		},
		{
			name:     "empty string",
			input:    "",
			wantHost: "",
			wantMsg:  "",
			wantOK:   false,
		},
		{
			name:     "IP with surrounding Japanese",
			input:    "ターゲット10.0.0.8を追加して脆弱性を調べて",
			wantHost: "10.0.0.8",
			wantMsg:  "ターゲットを追加して脆弱性を調べて",
			wantOK:   true,
		},
		// ドメイン名テストケース
		{
			name:     "Domain with Japanese",
			input:    "eighteen.htbをスキャンして",
			wantHost: "eighteen.htb",
			wantMsg:  "をスキャンして",
			wantOK:   true,
		},
		{
			name:     "Domain only",
			input:    "example.com",
			wantHost: "example.com",
			wantMsg:  "",
			wantOK:   true,
		},
		{
			name:     "Subdomain with Japanese",
			input:    "sub.domain.co.jp にペンテスト",
			wantHost: "sub.domain.co.jp",
			wantMsg:  "にペンテスト",
			wantOK:   true,
		},
		{
			name:     "no match plain text",
			input:    "run nmap scan",
			wantHost: "",
			wantMsg:  "",
			wantOK:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, msg, ok := extractHostFromText(tt.input)
			if ok != tt.wantOK {
				t.Errorf("ok: got %v, want %v", ok, tt.wantOK)
			}
			if host != tt.wantHost {
				t.Errorf("host: got %q, want %q", host, tt.wantHost)
			}
			if msg != tt.wantMsg {
				t.Errorf("msg: got %q, want %q", msg, tt.wantMsg)
			}
		})
	}
}

// newTestApp creates an App for testing with a bytes.Buffer for output.
func newTestApp(targets []*agent.Target) *App {
	a := NewApp(targets)
	a.testWriter = &bytes.Buffer{}
	return a
}

func TestHandleModelCommand_ListModels(t *testing.T) {
	t.Setenv("OPENROUTER_API_KEY", "sk-or-test")

	target := agent.NewTarget(1, "10.0.0.1")
	a := newTestApp([]*agent.Target{target})
	a.OpenRouterModelFetcher = func(context.Context) ([]brain.OpenRouterModel, error) {
		return []brain.OpenRouterModel{
			{ID: "openai/gpt-4o-mini", Name: "GPT-4o Mini"},
			{ID: "anthropic/claude-3.5-sonnet", Name: "Claude 3.5 Sonnet"},
		}, nil
	}

	a.handleModelCommand("/model")

	if a.inputMode != ModeSelect {
		t.Errorf("expected ModeSelect mode, got %d", a.inputMode)
	}
	if len(a.selectOpts) < 1 {
		t.Error("expected at least 1 model in select options")
	}
	found := false
	for _, opt := range a.selectOpts {
		if opt.Value == "openai/gpt-4o-mini" {
			found = true
		}
	}
	if !found {
		t.Error("expected 'openai/gpt-4o-mini' in select options")
	}
}

func TestHandleModelCommand_WithExactArg_SwitchesDirectly(t *testing.T) {
	t.Setenv("OPENROUTER_API_KEY", "sk-or-test")

	target := agent.NewTarget(1, "10.0.0.1")
	a := newTestApp([]*agent.Target{target})
	a.OpenRouterModelFetcher = func(context.Context) ([]brain.OpenRouterModel, error) {
		return []brain.OpenRouterModel{
			{ID: "openai/gpt-4o", Name: "GPT-4o"},
		}, nil
	}
	a.BrainFactory = func(hint brain.ConfigHint) (brain.Brain, error) {
		return nil, nil
	}

	a.handleModelCommand("/model openai/gpt-4o")

	if a.inputMode == ModeSelect {
		t.Errorf("expected direct switch mode, got select")
	}
	if a.CurrentProvider != "openrouter" {
		t.Errorf("CurrentProvider: got %q, want openrouter", a.CurrentProvider)
	}
	if a.CurrentModel != "openai/gpt-4o" {
		t.Errorf("CurrentModel: got %q, want openai/gpt-4o", a.CurrentModel)
	}
}

func TestHandleModelCommand_NoProviders(t *testing.T) {
	t.Setenv("OPENROUTER_API_KEY", "")

	target := agent.NewTarget(1, "10.0.0.1")
	a := newTestApp([]*agent.Target{target})

	a.handleModelCommand("/model")

	if a.inputMode == ModeSelect {
		t.Error("should not show select when no providers are available")
	}
	found := false
	for _, b := range target.Blocks {
		if b.Type == agent.BlockSystem {
			found = true
		}
	}
	if !found {
		t.Error("expected system block about no providers")
	}
}
