package tui

import (
	"bytes"
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

// newTestApp creates an App for testing with a bytes.Buffer for output.
func newTestApp(targets []*agent.Target) *App {
	a := NewApp(targets)
	a.testWriter = &bytes.Buffer{}
	return a
}

func TestHandleModelCommand_ListProviders(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "sk-test")
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "")
	t.Setenv("ANTHROPIC_AUTH_TOKEN", "")
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("OLLAMA_BASE_URL", "")

	target := agent.NewTarget(1, "10.0.0.1")
	a := newTestApp([]*agent.Target{target})

	a.handleModelCommand("/model")

	if a.inputMode != ModeSelect {
		t.Errorf("expected ModeSelect mode, got %d", a.inputMode)
	}
	if len(a.selectOpts) < 1 {
		t.Error("expected at least 1 provider in select options")
	}
	found := false
	for _, opt := range a.selectOpts {
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
	a := newTestApp([]*agent.Target{target})
	a.BrainFactory = func(hint brain.ConfigHint) (brain.Brain, error) {
		return nil, nil
	}

	a.handleModelCommand("/model openai/gpt-4o")

	if a.inputMode != ModeSelect {
		t.Errorf("expected ModeSelect mode, got %d", a.inputMode)
	}
}

func TestHandleModelCommand_NoProviders(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "")
	t.Setenv("ANTHROPIC_AUTH_TOKEN", "")
	t.Setenv("OLLAMA_BASE_URL", "")

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

func TestHandleApproveCommand_ShowState(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	a := newTestApp([]*agent.Target{target})
	runner := tools.NewCommandRunner(tools.NewRegistry(), tools.NewBlacklist(nil), tools.NewLogStore())
	a.Runner = runner

	a.handleApproveCommand("/approve")

	if a.inputMode != ModeSelect {
		t.Errorf("expected ModeSelect mode, got %d", a.inputMode)
	}
	if len(a.selectOpts) != 2 {
		t.Errorf("expected 2 options (ON/OFF), got %d", len(a.selectOpts))
	}
}

func TestHandleApproveCommand_WithArgs_ShowsSelectUI(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	a := newTestApp([]*agent.Target{target})
	runner := tools.NewCommandRunner(tools.NewRegistry(), tools.NewBlacklist(nil), tools.NewLogStore())
	a.Runner = runner

	a.handleApproveCommand("/approve on")

	if a.inputMode != ModeSelect {
		t.Errorf("expected ModeSelect mode, got %d", a.inputMode)
	}
	if len(a.selectOpts) != 2 {
		t.Errorf("expected 2 options (ON/OFF), got %d", len(a.selectOpts))
	}
}

func TestHandleApproveCommand_OffArgs_ShowsSelectUI(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	a := newTestApp([]*agent.Target{target})
	runner := tools.NewCommandRunner(tools.NewRegistry(), tools.NewBlacklist(nil), tools.NewLogStore())
	runner.SetAutoApprove(true)
	a.Runner = runner

	a.handleApproveCommand("/approve off")

	if a.inputMode != ModeSelect {
		t.Errorf("expected ModeSelect mode, got %d", a.inputMode)
	}
	if !runner.AutoApprove() {
		t.Error("auto-approve should remain ON until user selects from UI")
	}
}

func TestHandleApproveCommand_NilRunner(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	a := newTestApp([]*agent.Target{target})

	a.handleApproveCommand("/approve")

	found := false
	for _, b := range target.Blocks {
		if b.Type == agent.BlockSystem && b.SystemMsg == "Auto-approve not available" {
			found = true
		}
	}
	if !found {
		t.Error("expected system block about auto-approve not available")
	}
}
