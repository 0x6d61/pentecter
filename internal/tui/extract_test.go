package tui

import (
	"testing"

	"github.com/0x6d61/pentecter/internal/agent"
	"github.com/0x6d61/pentecter/internal/brain"
	"github.com/0x6d61/pentecter/internal/tools"
)

func TestExtractIPFromText(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantIP  string
		wantMsg string
		wantOK  bool
	}{
		{
			name:    "Japanese with IP",
			input:   "192.168.81.1をスキャンして",
			wantIP:  "192.168.81.1",
			wantMsg: "をスキャンして",
			wantOK:  true,
		},
		{
			name:    "English with IP",
			input:   "scan 10.0.0.5 please",
			wantIP:  "10.0.0.5",
			wantMsg: "scan please",
			wantOK:  true,
		},
		{
			name:    "IP only",
			input:   "192.168.1.1",
			wantIP:  "192.168.1.1",
			wantMsg: "",
			wantOK:  true,
		},
		{
			name:    "IP at end of text",
			input:   "please scan 172.16.0.1",
			wantIP:  "172.16.0.1",
			wantMsg: "please scan",
			wantOK:  true,
		},
		{
			name:    "no IP",
			input:   "run nmap scan",
			wantIP:  "",
			wantMsg: "",
			wantOK:  false,
		},
		{
			name:    "command prefix",
			input:   "/target 10.0.0.5",
			wantIP:  "",
			wantMsg: "",
			wantOK:  false,
		},
		{
			name:    "empty string",
			input:   "",
			wantIP:  "",
			wantMsg: "",
			wantOK:  false,
		},
		{
			name:    "IP with surrounding Japanese",
			input:   "ターゲット10.0.0.8を追加して脆弱性を調べて",
			wantIP:  "10.0.0.8",
			wantMsg: "ターゲットを追加して脆弱性を調べて",
			wantOK:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip, msg, ok := extractIPFromText(tt.input)
			if ok != tt.wantOK {
				t.Errorf("ok: got %v, want %v", ok, tt.wantOK)
			}
			if ip != tt.wantIP {
				t.Errorf("ip: got %q, want %q", ip, tt.wantIP)
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

	// Should have logged available providers
	found := false
	for _, log := range target.Logs {
		if log.Source == agent.SourceSystem && len(log.Message) > 0 {
			found = true
		}
	}
	if !found {
		t.Error("expected system log about available providers")
	}
}

func TestHandleModelCommand_SwitchProvider(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{target})

	factoryCalled := false
	m.BrainFactory = func(hint brain.ConfigHint) (brain.Brain, error) {
		factoryCalled = true
		if hint.Provider != brain.ProviderOpenAI {
			t.Errorf("provider: got %q, want openai", hint.Provider)
		}
		if hint.Model != "gpt-4o" {
			t.Errorf("model: got %q, want gpt-4o", hint.Model)
		}
		return nil, nil // stub
	}

	m.handleModelCommand("/model openai/gpt-4o")

	if !factoryCalled {
		t.Error("expected BrainFactory to be called")
	}
}

func TestHandleModelCommand_NoFactory(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{target})

	m.handleModelCommand("/model anthropic")

	// Should log that factory is not available
	found := false
	for _, log := range target.Logs {
		if log.Source == agent.SourceSystem && log.Message == "Model switching not available (no brain factory)" {
			found = true
		}
	}
	if !found {
		t.Error("expected error log about missing brain factory")
	}
}

func TestHandleApproveCommand_ShowState(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{target})
	runner := tools.NewCommandRunner(tools.NewRegistry(), tools.NewBlacklist(nil), tools.NewLogStore())
	m.Runner = runner

	m.handleApproveCommand("/approve")

	found := false
	for _, log := range target.Logs {
		if log.Source == agent.SourceSystem && log.Message == "Auto-approve: OFF" {
			found = true
		}
	}
	if !found {
		t.Error("expected system log showing auto-approve state OFF")
	}
}

func TestHandleApproveCommand_On(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{target})
	runner := tools.NewCommandRunner(tools.NewRegistry(), tools.NewBlacklist(nil), tools.NewLogStore())
	m.Runner = runner

	m.handleApproveCommand("/approve on")

	if !runner.AutoApprove() {
		t.Error("expected auto-approve to be enabled")
	}

	found := false
	for _, log := range target.Logs {
		if log.Source == agent.SourceSystem && log.Message == "Auto-approve: ON — all commands will execute without confirmation" {
			found = true
		}
	}
	if !found {
		t.Error("expected system log confirming auto-approve ON")
	}
}

func TestHandleApproveCommand_Off(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{target})
	runner := tools.NewCommandRunner(tools.NewRegistry(), tools.NewBlacklist(nil), tools.NewLogStore())
	runner.SetAutoApprove(true) // Start with ON
	m.Runner = runner

	m.handleApproveCommand("/approve off")

	if runner.AutoApprove() {
		t.Error("expected auto-approve to be disabled")
	}

	found := false
	for _, log := range target.Logs {
		if log.Source == agent.SourceSystem && log.Message == "Auto-approve: OFF — proposals will require confirmation" {
			found = true
		}
	}
	if !found {
		t.Error("expected system log confirming auto-approve OFF")
	}
}

func TestNewWithTargets_SetsSuggestions(t *testing.T) {
	m := NewWithTargets(nil)

	got := m.input.AvailableSuggestions()
	want := []string{"/model", "/approve", "/target"}

	if len(got) != len(want) {
		t.Fatalf("suggestions length: got %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("suggestions[%d]: got %q, want %q", i, got[i], want[i])
		}
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
