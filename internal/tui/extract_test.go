package tui

import (
	"testing"

	"github.com/0x6d61/pentecter/internal/agent"
	"github.com/0x6d61/pentecter/internal/brain"
	"github.com/0x6d61/pentecter/internal/tools"
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

func TestHandleModelCommand_ListProviders(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "sk-test")
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "")
	t.Setenv("ANTHROPIC_AUTH_TOKEN", "")
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("OLLAMA_BASE_URL", "")

	target := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{target})

	m.handleModelCommand("/model")

	// With providers available, should show select UI instead of log
	if m.inputMode != InputSelect {
		t.Errorf("expected InputSelect mode, got %d", m.inputMode)
	}
	if len(m.selectOptions) < 1 {
		t.Error("expected at least 1 provider in select options")
	}
	// Verify anthropic is in the options
	found := false
	for _, opt := range m.selectOptions {
		if opt.Value == "anthropic" {
			found = true
		}
	}
	if !found {
		t.Error("expected 'anthropic' in select options")
	}
}

func TestHandleModelCommand_WithArgs_ShowsSelectUI(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "sk-test")
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "")
	t.Setenv("ANTHROPIC_AUTH_TOKEN", "")
	t.Setenv("OLLAMA_BASE_URL", "")

	target := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{target})
	m.BrainFactory = func(hint brain.ConfigHint) (brain.Brain, error) {
		return nil, nil
	}

	// Args are ignored — always shows select UI
	m.handleModelCommand("/model openai/gpt-4o")

	if m.inputMode != InputSelect {
		t.Errorf("expected InputSelect mode, got %d", m.inputMode)
	}
}

func TestHandleModelCommand_NoProviders(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "")
	t.Setenv("ANTHROPIC_AUTH_TOKEN", "")
	t.Setenv("OLLAMA_BASE_URL", "")

	target := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{target})

	m.handleModelCommand("/model")

	// No providers → should log message, not show select
	if m.inputMode == InputSelect {
		t.Error("should not show select when no providers are available")
	}
	found := false
	for _, log := range target.Logs {
		if log.Source == agent.SourceSystem {
			found = true
		}
	}
	if !found {
		t.Error("expected system log about no providers")
	}
}

func TestHandleApproveCommand_ShowState(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{target})
	runner := tools.NewCommandRunner(tools.NewRegistry(), tools.NewBlacklist(nil), tools.NewLogStore())
	m.Runner = runner

	m.handleApproveCommand("/approve")

	// /approve without args now shows select UI instead of logging state
	if m.inputMode != InputSelect {
		t.Errorf("expected InputSelect mode, got %d", m.inputMode)
	}
	if len(m.selectOptions) != 2 {
		t.Errorf("expected 2 options (ON/OFF), got %d", len(m.selectOptions))
	}
}

func TestHandleApproveCommand_WithArgs_ShowsSelectUI(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{target})
	runner := tools.NewCommandRunner(tools.NewRegistry(), tools.NewBlacklist(nil), tools.NewLogStore())
	m.Runner = runner

	// Args are ignored — always shows select UI
	m.handleApproveCommand("/approve on")

	if m.inputMode != InputSelect {
		t.Errorf("expected InputSelect mode, got %d", m.inputMode)
	}
	if len(m.selectOptions) != 2 {
		t.Errorf("expected 2 options (ON/OFF), got %d", len(m.selectOptions))
	}
}

func TestHandleApproveCommand_OffArgs_ShowsSelectUI(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{target})
	runner := tools.NewCommandRunner(tools.NewRegistry(), tools.NewBlacklist(nil), tools.NewLogStore())
	runner.SetAutoApprove(true) // Start with ON
	m.Runner = runner

	// Args are ignored — always shows select UI
	m.handleApproveCommand("/approve off")

	if m.inputMode != InputSelect {
		t.Errorf("expected InputSelect mode, got %d", m.inputMode)
	}
	// Auto-approve should still be true (not changed until select callback)
	if !runner.AutoApprove() {
		t.Error("auto-approve should remain ON until user selects from UI")
	}
}

func TestHandleApproveCommand_NilRunner(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{target})
	// Runner is nil by default

	m.handleApproveCommand("/approve")

	found := false
	for _, log := range target.Logs {
		if log.Source == agent.SourceSystem && log.Message == "Auto-approve not available" {
			found = true
		}
	}
	if !found {
		t.Error("expected system log about auto-approve not available")
	}
}
