package tui

import (
	"testing"

	"github.com/0x6d61/pentecter/internal/agent"
)

// ---------------------------------------------------------------------------
// parseTargetInput
// ---------------------------------------------------------------------------

func TestParseTargetInput_ValidIP(t *testing.T) {
	host, ok := parseTargetInput("10.0.0.5")
	if !ok {
		t.Fatal("expected ok=true for valid IP")
	}
	if host != "10.0.0.5" {
		t.Errorf("expected host '10.0.0.5', got %q", host)
	}
}

func TestParseTargetInput_TargetCommand(t *testing.T) {
	host, ok := parseTargetInput("/target example.com")
	if !ok {
		t.Fatal("expected ok=true for /target command")
	}
	if host != "example.com" {
		t.Errorf("expected host 'example.com', got %q", host)
	}
}

func TestParseTargetInput_TargetCommandWithIP(t *testing.T) {
	host, ok := parseTargetInput("/target 192.168.1.1")
	if !ok {
		t.Fatal("expected ok=true for /target with IP")
	}
	if host != "192.168.1.1" {
		t.Errorf("expected host '192.168.1.1', got %q", host)
	}
}

func TestParseTargetInput_TargetCommandEmpty(t *testing.T) {
	_, ok := parseTargetInput("/target ")
	if ok {
		t.Error("expected ok=false for /target with empty host")
	}
}

func TestParseTargetInput_PlainText(t *testing.T) {
	_, ok := parseTargetInput("hello world")
	if ok {
		t.Error("expected ok=false for plain text")
	}
}

func TestParseTargetInput_DomainOnly(t *testing.T) {
	host, ok := parseTargetInput("example.com")
	if !ok {
		t.Fatal("expected ok=true for domain-only input")
	}
	if host != "example.com" {
		t.Errorf("expected host 'example.com', got %q", host)
	}
}

func TestParseTargetInput_DomainWithSubdomain(t *testing.T) {
	host, ok := parseTargetInput("sub.example.com")
	if !ok {
		t.Fatal("expected ok=true for subdomain")
	}
	if host != "sub.example.com" {
		t.Errorf("expected host 'sub.example.com', got %q", host)
	}
}

// ---------------------------------------------------------------------------
// handleInputLine
// ---------------------------------------------------------------------------

func TestHandleInputLine_NormalEmpty(t *testing.T) {
	a := newTestApp(nil)
	quit := a.handleInputLine("")
	if quit {
		t.Error("empty input should not quit")
	}
}

func TestHandleInputLine_ConfirmQuit_Yes(t *testing.T) {
	a := newTestApp(nil)
	a.inputMode = ModeConfirmQuit

	quit := a.handleInputLine("y")
	if !quit {
		t.Error("expected quit on 'y' in confirm quit mode")
	}
}

func TestHandleInputLine_ConfirmQuit_No(t *testing.T) {
	a := newTestApp(nil)
	a.inputMode = ModeConfirmQuit

	quit := a.handleInputLine("n")
	if quit {
		t.Error("expected no quit on 'n' in confirm quit mode")
	}
	if a.inputMode != ModeNormal {
		t.Errorf("expected ModeNormal after canceling quit, got %d", a.inputMode)
	}
}

func TestHandleInputLine_Select_Cancel(t *testing.T) {
	a := newTestApp(nil)
	a.inputMode = ModeSelect
	a.selectOpts = []SelectOption{{Label: "test", Value: "test"}}
	a.selectCb = func(a *App, v string) { t.Error("callback should not be called on cancel") }

	a.handleInputLine("q")
	if a.inputMode != ModeNormal {
		t.Errorf("expected ModeNormal after cancel, got %d", a.inputMode)
	}
}

func TestHandleInputLine_Select_ValidChoice(t *testing.T) {
	a := newTestApp(nil)
	a.inputMode = ModeSelect
	a.selectOpts = []SelectOption{
		{Label: "opt1", Value: "v1"},
		{Label: "opt2", Value: "v2"},
	}

	var called string
	a.selectCb = func(a *App, v string) { called = v }

	a.handleInputLine("2")
	if called != "v2" {
		t.Errorf("expected callback with 'v2', got %q", called)
	}
	if a.inputMode != ModeNormal {
		t.Errorf("expected ModeNormal after selection, got %d", a.inputMode)
	}
}

func TestHandleInputLine_Select_InvalidChoice(t *testing.T) {
	a := newTestApp(nil)
	a.inputMode = ModeSelect
	a.selectOpts = []SelectOption{{Label: "test", Value: "test"}}

	a.handleInputLine("99")
	// Should remain in select mode
	if a.inputMode != ModeSelect {
		t.Errorf("expected to remain in ModeSelect on invalid choice, got %d", a.inputMode)
	}
}

func TestHandleInputLine_Select_InvalidTrailingChars(t *testing.T) {
	a := newTestApp(nil)
	a.inputMode = ModeSelect
	a.selectOpts = []SelectOption{
		{Label: "opt1", Value: "v1"},
		{Label: "opt2", Value: "v2"},
	}

	var called string
	a.selectCb = func(a *App, v string) { called = v }

	a.handleInputLine("1abc")
	if called != "" {
		t.Errorf("callback should not be called for invalid numeric input, got %q", called)
	}
	if a.inputMode != ModeSelect {
		t.Errorf("expected ModeSelect to remain active, got %d", a.inputMode)
	}
}

// ---------------------------------------------------------------------------
// handleProposalInput
// ---------------------------------------------------------------------------

func TestHandleProposalInput_Approve(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	target.SetProposal(&agent.Proposal{
		Description: "Test scan",
		Tool:        "nmap",
		Args:        []string{"-sV", "10.0.0.1"},
	})
	a := newTestApp([]*agent.Target{target})
	approveCh := make(chan bool, 1)
	a.agentApproveMap[1] = approveCh
	a.inputMode = ModeProposal

	a.handleInputLine("y")

	// Check approval was sent
	select {
	case approved := <-approveCh:
		if !approved {
			t.Error("expected approval=true")
		}
	default:
		t.Error("expected approval to be sent to channel")
	}

	// Check mode reset
	if a.inputMode != ModeNormal {
		t.Errorf("expected ModeNormal after approval, got %d", a.inputMode)
	}

	// Check proposal cleared
	if target.GetProposal() != nil {
		t.Error("expected proposal to be cleared after approval")
	}
}

func TestHandleProposalInput_Reject(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	target.SetProposal(&agent.Proposal{
		Description: "Test scan",
		Tool:        "nmap",
		Args:        []string{"-sV"},
	})
	a := newTestApp([]*agent.Target{target})
	approveCh := make(chan bool, 1)
	a.agentApproveMap[1] = approveCh
	a.inputMode = ModeProposal

	a.handleInputLine("n")

	select {
	case approved := <-approveCh:
		if approved {
			t.Error("expected approval=false on rejection")
		}
	default:
		t.Error("expected rejection to be sent to channel")
	}

	if a.inputMode != ModeNormal {
		t.Errorf("expected ModeNormal after rejection, got %d", a.inputMode)
	}
}

// ---------------------------------------------------------------------------
// handleCommand
// ---------------------------------------------------------------------------

func TestHandleCommand_Unknown(t *testing.T) {
	a := newTestApp(nil)
	handled := a.handleCommand("/unknown")
	if handled {
		t.Error("expected unknown command to not be handled")
	}
}

func TestHandleCommand_StrictPrefixMatch(t *testing.T) {
	a := newTestApp(nil)
	if a.handleCommand("/approve-now") {
		t.Error("expected /approve-now to be treated as unknown command")
	}
	if a.handleCommand("/modelx") {
		t.Error("expected /modelx to be treated as unknown command")
	}
}

func TestHandleCommand_Fold(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	a := newTestApp([]*agent.Target{target})

	if a.logsExpanded {
		t.Error("expected logsExpanded=false initially")
	}

	a.handleCommand("/fold")

	if !a.logsExpanded {
		t.Error("expected logsExpanded=true after /fold")
	}
}

func TestHandleCommand_Status(t *testing.T) {
	a := newTestApp(nil)
	a.CurrentProvider = "anthropic"
	a.CurrentModel = "claude-sonnet-4-6"

	// Should not panic
	a.handleCommand("/status")
}

func TestHandleCommand_ApproveRemoved(t *testing.T) {
	a := newTestApp(nil)

	if a.handleCommand("/approve") {
		t.Fatal("expected /approve command to be unhandled")
	}
}

func TestHandleTargetsCommand_SwitchToProposalTarget(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	t2 := agent.NewTarget(2, "10.0.0.2")
	t2.SetProposal(&agent.Proposal{
		Description: "Run scan",
		Tool:        "nmap",
		Args:        []string{"-sV"},
	})
	a := newTestApp([]*agent.Target{t1, t2})

	a.handleTargetsCommand()
	a.handleInputLine("2")

	if a.selected != 1 {
		t.Fatalf("expected selected target index 1, got %d", a.selected)
	}
	if a.inputMode != ModeProposal {
		t.Fatalf("expected ModeProposal after switching to target with proposal, got %d", a.inputMode)
	}
}
