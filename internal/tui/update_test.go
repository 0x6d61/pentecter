package tui

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/0x6d61/pentecter/internal/agent"
	"github.com/0x6d61/pentecter/internal/brain"
	"github.com/0x6d61/pentecter/internal/tools"
)

// ---------------------------------------------------------------------------
// cycleFocus
// ---------------------------------------------------------------------------

func TestCycleFocus_ViewportToInput(t *testing.T) {
	m := NewWithTargets(nil)
	m.focus = FocusViewport

	m.cycleFocus()

	if m.focus != FocusInput {
		t.Errorf("expected FocusInput after cycling from FocusViewport, got %d", m.focus)
	}
}

func TestCycleFocus_InputToViewport(t *testing.T) {
	m := NewWithTargets(nil)
	m.focus = FocusInput

	m.cycleFocus()

	if m.focus != FocusViewport {
		t.Errorf("expected FocusViewport after cycling from FocusInput, got %d", m.focus)
	}
}

func TestCycleFocus_FullCycle(t *testing.T) {
	m := NewWithTargets(nil)
	m.focus = FocusViewport

	m.cycleFocus() // Viewport -> Input
	m.cycleFocus() // Input -> Viewport

	if m.focus != FocusViewport {
		t.Errorf("expected FocusViewport after full cycle, got %d", m.focus)
	}
}

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

func TestParseTargetInput_InvalidIP(t *testing.T) {
	_, ok := parseTargetInput("999.999.999.999")
	if ok {
		t.Error("expected ok=false for invalid IP")
	}
}

func TestParseTargetInput_EmptyString(t *testing.T) {
	_, ok := parseTargetInput("")
	if ok {
		t.Error("expected ok=false for empty string")
	}
}

func TestParseTargetInput_IPv6(t *testing.T) {
	host, ok := parseTargetInput("::1")
	if !ok {
		t.Fatal("expected ok=true for IPv6 loopback")
	}
	if host != "::1" {
		t.Errorf("expected host '::1', got %q", host)
	}
}

func TestParseTargetInput_DomainDirect(t *testing.T) {
	host, ok := parseTargetInput("eighteen.htb")
	if !ok {
		t.Fatal("expected ok=true for domain name")
	}
	if host != "eighteen.htb" {
		t.Errorf("expected host 'eighteen.htb', got %q", host)
	}
}

func TestParseTargetInput_TargetCommandDomain(t *testing.T) {
	host, ok := parseTargetInput("/target eighteen.htb")
	if !ok {
		t.Fatal("expected ok=true for /target with domain")
	}
	if host != "eighteen.htb" {
		t.Errorf("expected host 'eighteen.htb', got %q", host)
	}
}

func TestParseTargetInput_SubdomainDirect(t *testing.T) {
	host, ok := parseTargetInput("sub.domain.co.jp")
	if !ok {
		t.Fatal("expected ok=true for subdomain")
	}
	if host != "sub.domain.co.jp" {
		t.Errorf("expected host 'sub.domain.co.jp', got %q", host)
	}
}

func TestParseTargetInput_PlainWord_NoDot(t *testing.T) {
	_, ok := parseTargetInput("localhost")
	if ok {
		t.Error("expected ok=false for single word without dot")
	}
}

// ---------------------------------------------------------------------------
// targetByID
// ---------------------------------------------------------------------------

func TestTargetByID_Found(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	t2 := agent.NewTarget(2, "10.0.0.2")
	t3 := agent.NewTarget(3, "10.0.0.3")
	m := NewWithTargets([]*agent.Target{t1, t2, t3})

	got := m.targetByID(2)
	if got == nil {
		t.Fatal("expected to find target with ID=2")
	}
	if got.Host != "10.0.0.2" {
		t.Errorf("expected host '10.0.0.2', got %q", got.Host)
	}
}

func TestTargetByID_NotFound(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})

	got := m.targetByID(999)
	if got != nil {
		t.Errorf("expected nil for missing ID, got %+v", got)
	}
}

func TestTargetByID_EmptyTargets(t *testing.T) {
	m := NewWithTargets(nil)

	got := m.targetByID(1)
	if got != nil {
		t.Errorf("expected nil for empty targets, got %+v", got)
	}
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

func TestInit_NilAgentEvents(t *testing.T) {
	m := NewWithTargets(nil)

	cmd := m.Init()
	if cmd != nil {
		t.Error("expected nil cmd when agentEvents is nil")
	}
}

func TestInit_WithAgentEvents(t *testing.T) {
	ch := make(chan agent.Event, 1)
	m := NewWithTargets(nil)
	m.agentEvents = ch

	cmd := m.Init()
	if cmd == nil {
		t.Error("expected non-nil cmd when agentEvents is set")
	}
}

// ---------------------------------------------------------------------------
// ConnectTeam
// ---------------------------------------------------------------------------

func TestConnectTeam(t *testing.T) {
	m := NewWithTargets(nil)

	eventsCh := make(chan agent.Event, 1)
	approveMap := map[int]chan<- bool{1: make(chan bool, 1)}
	userMsgMap := map[int]chan<- string{1: make(chan string, 1)}

	cfg := agent.TeamConfig{
		Events: make(chan agent.Event, 10),
		Brain:  nil,
		Runner: nil,
	}
	team := agent.NewTeam(cfg)

	m.ConnectTeam(team, eventsCh, approveMap, userMsgMap)

	if m.team == nil {
		t.Error("expected team to be set")
	}
	if m.agentEvents == nil {
		t.Error("expected agentEvents to be set")
	}
	if len(m.agentApproveMap) != 1 {
		t.Errorf("expected 1 entry in agentApproveMap, got %d", len(m.agentApproveMap))
	}
	if len(m.agentUserMsgMap) != 1 {
		t.Errorf("expected 1 entry in agentUserMsgMap, got %d", len(m.agentUserMsgMap))
	}
}

// ---------------------------------------------------------------------------
// activeTarget
// ---------------------------------------------------------------------------

func TestActiveTarget_Valid(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.selected = 0

	got := m.activeTarget()
	if got == nil {
		t.Fatal("expected non-nil active target")
	}
	if got.Host != "10.0.0.1" {
		t.Errorf("expected host '10.0.0.1', got %q", got.Host)
	}
}

func TestActiveTarget_NegativeIndex(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.selected = -1

	got := m.activeTarget()
	if got != nil {
		t.Errorf("expected nil for negative index, got %+v", got)
	}
}

func TestActiveTarget_IndexOutOfBounds(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.selected = 5

	got := m.activeTarget()
	if got != nil {
		t.Errorf("expected nil for out-of-bounds index, got %+v", got)
	}
}

func TestActiveTarget_EmptyTargets(t *testing.T) {
	m := NewWithTargets(nil)
	m.selected = 0

	got := m.activeTarget()
	if got != nil {
		t.Errorf("expected nil for empty targets, got %+v", got)
	}
}

// ---------------------------------------------------------------------------
// submitInput
// ---------------------------------------------------------------------------

func TestSubmitInput_EmptyInput(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.input.SetValue("")

	blocksBefore := len(t1.Blocks)
	m.submitInput()

	if len(t1.Blocks) != blocksBefore {
		t.Error("empty input should not add any block")
	}
}

func TestSubmitInput_WhitespaceOnly(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.input.SetValue("   ")

	blocksBefore := len(t1.Blocks)
	m.submitInput()

	if len(t1.Blocks) != blocksBefore {
		t.Error("whitespace-only input should not add any block")
	}
}

func TestSubmitInput_NormalText(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true
	m.input.SetValue("scan the target")

	blocksBefore := len(t1.Blocks)
	m.submitInput()

	if len(t1.Blocks) != blocksBefore+1 {
		t.Fatalf("expected 1 new block, got %d", len(t1.Blocks)-blocksBefore)
	}
	lastBlock := t1.Blocks[len(t1.Blocks)-1]
	if lastBlock.Type != agent.BlockUserInput {
		t.Errorf("expected BlockUserInput, got %d", lastBlock.Type)
	}
	if lastBlock.UserText != "scan the target" {
		t.Errorf("expected UserText 'scan the target', got %q", lastBlock.UserText)
	}
	// Input should be cleared
	if m.input.Value() != "" {
		t.Errorf("expected input to be cleared, got %q", m.input.Value())
	}
}

func TestSubmitInput_ApproveRouting(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	runner := tools.NewCommandRunner(tools.NewRegistry(), tools.NewBlacklist(nil), tools.NewLogStore())
	m.Runner = runner
	m.input.SetValue("/approve")

	m.submitInput()

	if m.inputMode != InputSelect {
		t.Errorf("expected InputSelect mode after /approve, got %d", m.inputMode)
	}
}

func TestSubmitInput_ModelRouting(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "sk-test")
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "")
	t.Setenv("ANTHROPIC_AUTH_TOKEN", "")
	t.Setenv("OLLAMA_BASE_URL", "")

	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.BrainFactory = func(hint brain.ConfigHint) (brain.Brain, error) {
		return nil, nil
	}
	m.input.SetValue("/model")

	m.submitInput()

	if m.inputMode != InputSelect {
		t.Errorf("expected InputSelect mode after /model, got %d", m.inputMode)
	}
}

func TestSubmitInput_ClearsInputValue(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true
	m.input.SetValue("hello")

	m.submitInput()

	if m.input.Value() != "" {
		t.Errorf("expected input to be cleared after submit, got %q", m.input.Value())
	}
}

// ---------------------------------------------------------------------------
// handleAgentEvent
// ---------------------------------------------------------------------------

func TestHandleAgentEvent_EventLog(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true

	blocksBefore := len(t1.Blocks)
	_ = m.handleAgentEvent(agent.Event{
		TargetID: 1,
		Type:     agent.EventLog,
		Source:   agent.SourceAI,
		Message:  "Found open port 80",
	})

	if len(t1.Blocks) != blocksBefore+1 {
		t.Fatalf("expected 1 new block, got %d", len(t1.Blocks)-blocksBefore)
	}
	lastBlock := t1.Blocks[len(t1.Blocks)-1]
	if lastBlock.Type != agent.BlockAIMessage {
		t.Errorf("expected BlockAIMessage, got %d", lastBlock.Type)
	}
	if lastBlock.Message != "Found open port 80" {
		t.Errorf("unexpected message: %q", lastBlock.Message)
	}
}

func TestHandleAgentEvent_EventProposal(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true

	proposal := &agent.Proposal{
		Description: "Run nmap",
		Tool:        "nmap",
		Args:        []string{"-sV", "10.0.0.1"},
	}
	_ = m.handleAgentEvent(agent.Event{
		TargetID: 1,
		Type:     agent.EventProposal,
		Proposal: proposal,
	})

	if t1.Proposal == nil {
		t.Fatal("expected proposal to be set")
	}
	if t1.Proposal.Description != "Run nmap" {
		t.Errorf("expected description 'Run nmap', got %q", t1.Proposal.Description)
	}
	if t1.Status != agent.StatusPaused {
		t.Errorf("expected StatusPaused, got %q", t1.Status)
	}
}

func TestHandleAgentEvent_EventProposal_NilProposal(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true

	blocksBefore := len(t1.Blocks)
	_ = m.handleAgentEvent(agent.Event{
		TargetID: 1,
		Type:     agent.EventProposal,
		Proposal: nil,
	})

	// nil proposal should not set anything
	if t1.Proposal != nil {
		t.Error("expected proposal to remain nil")
	}
	// No block should be added for nil proposal
	if len(t1.Blocks) != blocksBefore {
		t.Errorf("expected no new blocks for nil proposal, got %d new", len(t1.Blocks)-blocksBefore)
	}
}

func TestHandleAgentEvent_EventComplete(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true

	blocksBefore := len(t1.Blocks)
	_ = m.handleAgentEvent(agent.Event{
		TargetID: 1,
		Type:     agent.EventComplete,
		Message:  "Assessment complete",
	})

	if len(t1.Blocks) != blocksBefore+1 {
		t.Fatalf("expected 1 new block, got %d", len(t1.Blocks)-blocksBefore)
	}
	lastBlock := t1.Blocks[len(t1.Blocks)-1]
	if !strings.HasPrefix(lastBlock.SystemMsg, "\u2705") {
		t.Errorf("expected complete message to start with checkmark, got %q", lastBlock.SystemMsg)
	}
}

func TestHandleAgentEvent_EventError(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true

	blocksBefore := len(t1.Blocks)
	_ = m.handleAgentEvent(agent.Event{
		TargetID: 1,
		Type:     agent.EventError,
		Message:  "Connection refused",
	})

	if len(t1.Blocks) != blocksBefore+1 {
		t.Fatalf("expected 1 new block, got %d", len(t1.Blocks)-blocksBefore)
	}
	lastBlock := t1.Blocks[len(t1.Blocks)-1]
	if !strings.Contains(lastBlock.SystemMsg, "Connection refused") {
		t.Errorf("expected error message to contain 'Connection refused', got %q", lastBlock.SystemMsg)
	}
}

func TestHandleAgentEvent_EventAddTarget_NoTeam(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true
	// team is nil

	targetsBefore := len(m.targets)
	_ = m.handleAgentEvent(agent.Event{
		TargetID: 1,
		Type:     agent.EventAddTarget,
		NewHost:  "10.0.0.2",
	})

	// Without a team, addTarget should not be called
	if len(m.targets) != targetsBefore {
		t.Errorf("expected no new target without team, got %d targets", len(m.targets))
	}
}

func TestHandleAgentEvent_EventStalled(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true

	blocksBefore := len(t1.Blocks)
	_ = m.handleAgentEvent(agent.Event{
		TargetID: 1,
		Type:     agent.EventStalled,
		Message:  "Agent stuck",
	})

	// EventStalled adds 2 blocks
	if len(t1.Blocks) != blocksBefore+2 {
		t.Fatalf("expected 2 new blocks for stalled event, got %d", len(t1.Blocks)-blocksBefore)
	}
	if !strings.HasPrefix(t1.Blocks[blocksBefore].SystemMsg, "\u26a0") {
		t.Errorf("expected stalled message to start with warning, got %q", t1.Blocks[blocksBefore].SystemMsg)
	}
	if !strings.Contains(t1.Blocks[blocksBefore+1].SystemMsg, "Type a message") {
		t.Errorf("expected guidance message, got %q", t1.Blocks[blocksBefore+1].SystemMsg)
	}
}

func TestHandleAgentEvent_FallbackToActiveTarget(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true

	blocksBefore := len(t1.Blocks)
	// Send event for non-existent target ID — should fall back to active target
	_ = m.handleAgentEvent(agent.Event{
		TargetID: 999,
		Type:     agent.EventLog,
		Source:   agent.SourceSystem,
		Message:  "Fallback test",
	})

	if len(t1.Blocks) != blocksBefore+1 {
		t.Fatalf("expected 1 new block via fallback, got %d", len(t1.Blocks)-blocksBefore)
	}
	lastBlock := t1.Blocks[len(t1.Blocks)-1]
	if lastBlock.SystemMsg != "Fallback test" {
		t.Errorf("unexpected message: %q", lastBlock.SystemMsg)
	}
}

func TestHandleAgentEvent_NoTargets_NoOp(t *testing.T) {
	m := NewWithTargets(nil)
	m.handleResize(120, 40)
	m.ready = true

	// Should not panic when no targets exist
	_ = m.handleAgentEvent(agent.Event{
		TargetID: 1,
		Type:     agent.EventLog,
		Source:   agent.SourceSystem,
		Message:  "No target",
	})
}

func TestHandleAgentEvent_EventLog_CorrectTarget(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	t2 := agent.NewTarget(2, "10.0.0.2")
	m := NewWithTargets([]*agent.Target{t1, t2})
	m.handleResize(120, 40)
	m.ready = true
	m.selected = 0 // t1 is active

	blocks1Before := len(t1.Blocks)
	blocks2Before := len(t2.Blocks)

	// Send event for t2 (not the active target)
	_ = m.handleAgentEvent(agent.Event{
		TargetID: 2,
		Type:     agent.EventLog,
		Source:   agent.SourceAI,
		Message:  "Target 2 message",
	})

	// t2 should receive the block
	if len(t2.Blocks) != blocks2Before+1 {
		t.Errorf("expected 1 new block on t2, got %d", len(t2.Blocks)-blocks2Before)
	}
	// t1 should NOT receive the block
	if len(t1.Blocks) != blocks1Before {
		t.Errorf("expected no new blocks on t1, got %d", len(t1.Blocks)-blocks1Before)
	}
}

// ---------------------------------------------------------------------------
// handleAgentEvent — EventTurnStart
// ---------------------------------------------------------------------------

func TestHandleAgentEvent_EventTurnStart(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true

	blocksBefore := len(t1.Blocks)
	_ = m.handleAgentEvent(agent.Event{
		TargetID:   1,
		Type:       agent.EventTurnStart,
		TurnNumber: 3,
	})

	// EventTurnStart does not add blocks in new UI
	if len(t1.Blocks) != blocksBefore {
		t.Errorf("expected no new blocks for turn start, got %d", len(t1.Blocks)-blocksBefore)
	}
}

// ---------------------------------------------------------------------------
// extractHostFromText — invalid IP to cover ParseIP failure branch
// ---------------------------------------------------------------------------

func TestExtractHostFromText_InvalidIP(t *testing.T) {
	// 999.999.999.999 matches the IPv4 regex pattern but fails net.ParseIP;
	// however it also does NOT match domainRe (purely numeric labels),
	// so this should return ok=false.
	_, _, ok := extractHostFromText("scan 999.999.999.999 please")
	if ok {
		t.Error("expected ok=false for invalid IP 999.999.999.999")
	}
}

func TestExtractHostFromText_InvalidIP_300(t *testing.T) {
	_, _, ok := extractHostFromText("300.400.500.600")
	if ok {
		t.Error("expected ok=false for 300.400.500.600")
	}
}

// ---------------------------------------------------------------------------
// Update with tea.KeyMsg (Tab key)
// ---------------------------------------------------------------------------

func TestUpdate_TabCyclesFocus(t *testing.T) {
	m := NewWithTargets(nil)
	m.handleResize(120, 40)
	m.ready = true
	m.focus = FocusViewport

	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyTab})
	rm := result.(Model)

	if rm.focus != FocusInput {
		t.Errorf("expected FocusInput after Tab from FocusViewport, got %d", rm.focus)
	}
}

func TestUpdate_CtrlC_ShowsConfirmDialog(t *testing.T) {
	m := NewWithTargets(nil)
	m.handleResize(120, 40)
	m.ready = true

	result, cmd := m.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	rm := result.(Model)

	// Ctrl+C should NOT quit immediately — it should show the confirmation dialog
	if cmd != nil {
		t.Error("expected nil cmd on Ctrl+C (should not quit immediately)")
	}
	if rm.inputMode != InputConfirmQuit {
		t.Errorf("expected InputConfirmQuit mode, got %d", rm.inputMode)
	}
}

func TestConfirmQuit_Y_Quits(t *testing.T) {
	m := NewWithTargets(nil)
	m.handleResize(120, 40)
	m.ready = true
	m.inputMode = InputConfirmQuit

	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'y'}})
	if cmd == nil {
		t.Error("expected non-nil quit cmd on Y in confirm dialog")
	}
}

func TestConfirmQuit_UpperY_Quits(t *testing.T) {
	m := NewWithTargets(nil)
	m.handleResize(120, 40)
	m.ready = true
	m.inputMode = InputConfirmQuit

	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'Y'}})
	if cmd == nil {
		t.Error("expected non-nil quit cmd on Y in confirm dialog")
	}
}

func TestConfirmQuit_N_Cancels(t *testing.T) {
	m := NewWithTargets(nil)
	m.handleResize(120, 40)
	m.ready = true
	m.inputMode = InputConfirmQuit

	result, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'n'}})
	rm := result.(Model)

	if cmd != nil {
		t.Error("expected nil cmd on N (should not quit)")
	}
	if rm.inputMode != InputNormal {
		t.Errorf("expected InputNormal after N, got %d", rm.inputMode)
	}
}

func TestConfirmQuit_Esc_Cancels(t *testing.T) {
	m := NewWithTargets(nil)
	m.handleResize(120, 40)
	m.ready = true
	m.inputMode = InputConfirmQuit

	result, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	rm := result.(Model)

	if cmd != nil {
		t.Error("expected nil cmd on Esc (should not quit)")
	}
	if rm.inputMode != InputNormal {
		t.Errorf("expected InputNormal after Esc, got %d", rm.inputMode)
	}
}

func TestConfirmQuit_OtherKey_Ignored(t *testing.T) {
	m := NewWithTargets(nil)
	m.handleResize(120, 40)
	m.ready = true
	m.inputMode = InputConfirmQuit

	result, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'x'}})
	rm := result.(Model)

	// Other keys should not quit or cancel — dialog stays
	if cmd != nil {
		t.Error("expected nil cmd for non-y/n/esc key")
	}
	if rm.inputMode != InputConfirmQuit {
		t.Errorf("expected InputConfirmQuit to persist, got %d", rm.inputMode)
	}
}

func TestConfirmQuit_CtrlC_InSelectMode(t *testing.T) {
	m := NewWithTargets(nil)
	m.handleResize(120, 40)
	m.ready = true
	m.inputMode = InputSelect
	m.selectOptions = []SelectOption{{Label: "A", Value: "a"}}

	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	rm := result.(Model)

	// Ctrl+C should override select mode and show confirm dialog
	if rm.inputMode != InputConfirmQuit {
		t.Errorf("expected InputConfirmQuit even in select mode, got %d", rm.inputMode)
	}
}

// ---------------------------------------------------------------------------
// Update with WindowSizeMsg
// ---------------------------------------------------------------------------

func TestUpdate_WindowSizeMsg(t *testing.T) {
	m := NewWithTargets(nil)

	result, _ := m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	rm := result.(Model)

	if !rm.ready {
		t.Error("expected ready=true after WindowSizeMsg")
	}
	if rm.width != 100 {
		t.Errorf("expected width=100, got %d", rm.width)
	}
	if rm.height != 30 {
		t.Errorf("expected height=30, got %d", rm.height)
	}
}

// ---------------------------------------------------------------------------
// submitInput — textarea multiline support
// ---------------------------------------------------------------------------

func TestSubmitInput_MultilineViaTextarea(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true

	// textarea.SetValue supports multiline text directly
	m.input.SetValue("line 1\nline 2\nline 3")

	m.submitInput()

	// Should have submitted all lines as a single block
	lastBlock := t1.Blocks[len(t1.Blocks)-1]
	if !strings.Contains(lastBlock.UserText, "line 1") {
		t.Errorf("expected multiline message to contain 'line 1', got %q", lastBlock.UserText)
	}
	if !strings.Contains(lastBlock.UserText, "line 3") {
		t.Errorf("expected multiline message to contain 'line 3', got %q", lastBlock.UserText)
	}
	// Input should be cleared after submit
	if m.input.Value() != "" {
		t.Errorf("expected input to be cleared after submit, got %q", m.input.Value())
	}
}

func TestSubmitInput_TextareaReset(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true

	m.input.SetValue("some text")
	m.submitInput()

	// After submit, textarea should be reset (empty)
	if m.input.Value() != "" {
		t.Errorf("expected textarea to be reset after submit, got %q", m.input.Value())
	}
}

// ---------------------------------------------------------------------------
// handleAgentEvent — Block-based events
// ---------------------------------------------------------------------------

func TestHandleAgentEvent_EventThinkStart(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true

	blocksBefore := len(t1.Blocks)

	_ = m.handleAgentEvent(agent.Event{
		TargetID: 1,
		Type:     agent.EventThinkStart,
	})

	// Should add a ThinkingBlock
	if len(t1.Blocks) != blocksBefore+1 {
		t.Fatalf("expected 1 new block for ThinkStart, got %d", len(t1.Blocks)-blocksBefore)
	}
	lastBlock := t1.Blocks[len(t1.Blocks)-1]
	if lastBlock.Type != agent.BlockThinking {
		t.Errorf("expected BlockThinking, got %d", lastBlock.Type)
	}
	if lastBlock.ThinkingDone {
		t.Error("ThinkingDone should be false on new ThinkStart block")
	}
}

func TestHandleAgentEvent_EventThinkDone(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true

	// First add a thinking block
	t1.AddBlock(agent.NewThinkingBlock())

	_ = m.handleAgentEvent(agent.Event{
		TargetID: 1,
		Type:     agent.EventThinkDone,
		Duration: 2500 * time.Millisecond,
	})

	// The last thinking block should be marked done
	lastBlock := t1.LastBlock()
	if lastBlock == nil {
		t.Fatal("expected a block to exist")
	}
	if !lastBlock.ThinkingDone {
		t.Error("expected ThinkingDone to be true after EventThinkDone")
	}
	if lastBlock.ThinkDuration != 2500*time.Millisecond {
		t.Errorf("expected ThinkDuration 2.5s, got %v", lastBlock.ThinkDuration)
	}
}

func TestHandleAgentEvent_EventThinkDone_NoBlock(t *testing.T) {
	// ThinkDone with no blocks should not panic
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true

	_ = m.handleAgentEvent(agent.Event{
		TargetID: 1,
		Type:     agent.EventThinkDone,
		Duration: 1 * time.Second,
	})
	// Should not panic — no assertions needed beyond not crashing
}

func TestHandleAgentEvent_EventCmdStart(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true

	blocksBefore := len(t1.Blocks)

	_ = m.handleAgentEvent(agent.Event{
		TargetID: 1,
		Type:     agent.EventCmdStart,
		Message:  "nmap -sV 10.0.0.1",
	})

	if len(t1.Blocks) != blocksBefore+1 {
		t.Fatalf("expected 1 new block for CmdStart, got %d", len(t1.Blocks)-blocksBefore)
	}
	lastBlock := t1.Blocks[len(t1.Blocks)-1]
	if lastBlock.Type != agent.BlockCommand {
		t.Errorf("expected BlockCommand, got %d", lastBlock.Type)
	}
	if lastBlock.Command != "nmap -sV 10.0.0.1" {
		t.Errorf("expected Command 'nmap -sV 10.0.0.1', got %q", lastBlock.Command)
	}
	if lastBlock.Completed {
		t.Error("Completed should be false on new CmdStart block")
	}
}

func TestHandleAgentEvent_EventCmdOutput(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true

	// First add an incomplete command block
	t1.AddBlock(agent.NewCommandBlock("nmap -sV 10.0.0.1"))

	_ = m.handleAgentEvent(agent.Event{
		TargetID:   1,
		Type:       agent.EventCmdOutput,
		OutputLine: "PORT   STATE SERVICE",
	})

	lastBlock := t1.LastBlock()
	if len(lastBlock.Output) != 1 {
		t.Fatalf("expected 1 output line, got %d", len(lastBlock.Output))
	}
	if lastBlock.Output[0] != "PORT   STATE SERVICE" {
		t.Errorf("expected output line 'PORT   STATE SERVICE', got %q", lastBlock.Output[0])
	}
}

func TestHandleAgentEvent_EventCmdOutput_MultipleLines(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true

	t1.AddBlock(agent.NewCommandBlock("nmap -sV 10.0.0.1"))

	_ = m.handleAgentEvent(agent.Event{TargetID: 1, Type: agent.EventCmdOutput, OutputLine: "line 1"})
	_ = m.handleAgentEvent(agent.Event{TargetID: 1, Type: agent.EventCmdOutput, OutputLine: "line 2"})
	_ = m.handleAgentEvent(agent.Event{TargetID: 1, Type: agent.EventCmdOutput, OutputLine: "line 3"})

	lastBlock := t1.LastBlock()
	if len(lastBlock.Output) != 3 {
		t.Fatalf("expected 3 output lines, got %d", len(lastBlock.Output))
	}
}

func TestHandleAgentEvent_EventCmdOutput_NoBlock(t *testing.T) {
	// CmdOutput with no blocks should not panic
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true

	_ = m.handleAgentEvent(agent.Event{
		TargetID:   1,
		Type:       agent.EventCmdOutput,
		OutputLine: "orphan output",
	})
	// Should not panic
}

func TestHandleAgentEvent_EventCmdOutput_CompletedBlock(t *testing.T) {
	// CmdOutput should not append to a completed block
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true

	block := agent.NewCommandBlock("echo test")
	block.Completed = true
	t1.AddBlock(block)

	_ = m.handleAgentEvent(agent.Event{
		TargetID:   1,
		Type:       agent.EventCmdOutput,
		OutputLine: "should not append",
	})

	if len(block.Output) != 0 {
		t.Errorf("expected no output on completed block, got %d lines", len(block.Output))
	}
}

func TestHandleAgentEvent_EventCmdDone(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true

	t1.AddBlock(agent.NewCommandBlock("echo done-test"))

	_ = m.handleAgentEvent(agent.Event{
		TargetID: 1,
		Type:     agent.EventCmdDone,
		ExitCode: 0,
		Duration: 1500 * time.Millisecond,
	})

	lastBlock := t1.LastBlock()
	if !lastBlock.Completed {
		t.Error("expected Completed to be true after EventCmdDone")
	}
	if lastBlock.ExitCode != 0 {
		t.Errorf("expected ExitCode 0, got %d", lastBlock.ExitCode)
	}
	if lastBlock.Duration != 1500*time.Millisecond {
		t.Errorf("expected Duration 1.5s, got %v", lastBlock.Duration)
	}
}

func TestHandleAgentEvent_EventCmdDone_NoBlock(t *testing.T) {
	// CmdDone with no blocks should not panic
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true

	_ = m.handleAgentEvent(agent.Event{
		TargetID: 1,
		Type:     agent.EventCmdDone,
		ExitCode: 1,
		Duration: 500 * time.Millisecond,
	})
	// Should not panic
}

func TestHandleAgentEvent_EventCmdDone_NonZeroExit(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true

	t1.AddBlock(agent.NewCommandBlock("false"))

	_ = m.handleAgentEvent(agent.Event{
		TargetID: 1,
		Type:     agent.EventCmdDone,
		ExitCode: 1,
		Duration: 200 * time.Millisecond,
	})

	lastBlock := t1.LastBlock()
	if !lastBlock.Completed {
		t.Error("expected Completed to be true")
	}
	if lastBlock.ExitCode != 1 {
		t.Errorf("expected ExitCode 1, got %d", lastBlock.ExitCode)
	}
}

func TestHandleAgentEvent_EventSubTaskStart(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true

	blocksBefore := len(t1.Blocks)

	_ = m.handleAgentEvent(agent.Event{
		TargetID: 1,
		Type:     agent.EventSubTaskStart,
		TaskID:   "task-1",
		Message:  "Enumerate SMB shares",
	})

	if len(t1.Blocks) != blocksBefore+1 {
		t.Fatalf("expected 1 new block for SubTaskStart, got %d", len(t1.Blocks)-blocksBefore)
	}
	lastBlock := t1.Blocks[len(t1.Blocks)-1]
	if lastBlock.Type != agent.BlockSubTask {
		t.Errorf("expected BlockSubTask, got %d", lastBlock.Type)
	}
	if lastBlock.TaskID != "task-1" {
		t.Errorf("expected TaskID 'task-1', got %q", lastBlock.TaskID)
	}
	if lastBlock.TaskGoal != "Enumerate SMB shares" {
		t.Errorf("expected TaskGoal 'Enumerate SMB shares', got %q", lastBlock.TaskGoal)
	}
	if lastBlock.TaskDone {
		t.Error("TaskDone should be false on new SubTaskStart block")
	}
}

func TestHandleAgentEvent_EventCmdStart_CmdOutput_CmdDone_FullFlow(t *testing.T) {
	// Test the full flow: CmdStart -> CmdOutput -> CmdDone
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true

	// CmdStart creates the block
	_ = m.handleAgentEvent(agent.Event{
		TargetID: 1,
		Type:     agent.EventCmdStart,
		Message:  "echo hello",
	})

	// CmdOutput appends to it
	_ = m.handleAgentEvent(agent.Event{
		TargetID:   1,
		Type:       agent.EventCmdOutput,
		OutputLine: "hello",
	})

	// CmdDone completes it
	_ = m.handleAgentEvent(agent.Event{
		TargetID: 1,
		Type:     agent.EventCmdDone,
		ExitCode: 0,
		Duration: 100 * time.Millisecond,
	})

	if len(t1.Blocks) != 1 {
		t.Fatalf("expected 1 block for full CmdStart/Output/Done flow, got %d", len(t1.Blocks))
	}
	block := t1.Blocks[0]
	if block.Command != "echo hello" {
		t.Errorf("expected Command 'echo hello', got %q", block.Command)
	}
	if len(block.Output) != 1 || block.Output[0] != "hello" {
		t.Errorf("expected Output ['hello'], got %v", block.Output)
	}
	if !block.Completed {
		t.Error("expected Completed=true")
	}
	if block.ExitCode != 0 {
		t.Errorf("expected ExitCode 0, got %d", block.ExitCode)
	}
	if block.Duration != 100*time.Millisecond {
		t.Errorf("expected Duration 100ms, got %v", block.Duration)
	}
}

func TestHandleAgentEvent_ThinkStart_ThinkDone_FullFlow(t *testing.T) {
	// Test the full flow: ThinkStart -> ThinkDone
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true

	// ThinkStart creates a thinking block
	_ = m.handleAgentEvent(agent.Event{
		TargetID: 1,
		Type:     agent.EventThinkStart,
	})

	// ThinkDone marks it complete
	_ = m.handleAgentEvent(agent.Event{
		TargetID: 1,
		Type:     agent.EventThinkDone,
		Duration: 3 * time.Second,
	})

	if len(t1.Blocks) != 1 {
		t.Fatalf("expected 1 block for ThinkStart/Done flow, got %d", len(t1.Blocks))
	}
	block := t1.Blocks[0]
	if block.Type != agent.BlockThinking {
		t.Errorf("expected BlockThinking, got %d", block.Type)
	}
	if !block.ThinkingDone {
		t.Error("expected ThinkingDone=true")
	}
	if block.ThinkDuration != 3*time.Second {
		t.Errorf("expected ThinkDuration 3s, got %v", block.ThinkDuration)
	}
}

// ---------------------------------------------------------------------------
// Spinner integration tests
// ---------------------------------------------------------------------------

func TestHasActiveSpinner_NoTargets(t *testing.T) {
	m := NewWithTargets(nil)
	if m.hasActiveSpinner() {
		t.Error("expected false when no targets")
	}
}

func TestHasActiveSpinner_NoActiveBlocks(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})

	b := agent.NewThinkingBlock()
	b.ThinkingDone = true
	t1.AddBlock(b)

	if m.hasActiveSpinner() {
		t.Error("expected false when all thinking blocks are done")
	}
}

func TestHasActiveSpinner_ActiveThinking(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})

	t1.AddBlock(agent.NewThinkingBlock())

	if !m.hasActiveSpinner() {
		t.Error("expected true when there is an active thinking block")
	}
}

func TestHasActiveSpinner_ActiveSubTask(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})

	t1.AddBlock(agent.NewSubTaskBlock("task-1", "Scan ports"))

	if !m.hasActiveSpinner() {
		t.Error("expected true when there is an active subtask block")
	}
}

func TestHasActiveSpinner_CompletedSubTask(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})

	b := agent.NewSubTaskBlock("task-1", "Scan ports")
	b.TaskDone = true
	t1.AddBlock(b)

	if m.hasActiveSpinner() {
		t.Error("expected false when all subtask blocks are done")
	}
}

func TestHasActiveSpinner_MixedBlocks(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})

	done := agent.NewThinkingBlock()
	done.ThinkingDone = true
	t1.AddBlock(done)
	t1.AddBlock(agent.NewSubTaskBlock("task-1", "Active task"))

	if !m.hasActiveSpinner() {
		t.Error("expected true when at least one subtask is active")
	}
}

func TestHandleAgentEvent_ThinkStart_StartsSpinner(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true

	cmd := m.handleAgentEvent(agent.Event{
		TargetID: 1,
		Type:     agent.EventThinkStart,
	})

	if !m.spinning {
		t.Error("expected spinning=true after EventThinkStart")
	}
	if cmd == nil {
		t.Error("expected non-nil tea.Cmd (spinner.Tick) from EventThinkStart")
	}
}

func TestHandleAgentEvent_ThinkDone_StopsSpinner(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true

	_ = m.handleAgentEvent(agent.Event{
		TargetID: 1,
		Type:     agent.EventThinkStart,
	})

	_ = m.handleAgentEvent(agent.Event{
		TargetID: 1,
		Type:     agent.EventThinkDone,
		Duration: 2 * time.Second,
	})

	if m.spinning {
		t.Error("expected spinning=false after EventThinkDone with no remaining active blocks")
	}
}

func TestHandleAgentEvent_ThinkDone_KeepsSpinning_WhenOtherActive(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true

	_ = m.handleAgentEvent(agent.Event{
		TargetID: 1,
		Type:     agent.EventSubTaskStart,
		TaskID:   "task-1",
		Message:  "Running exploit",
	})

	_ = m.handleAgentEvent(agent.Event{
		TargetID: 1,
		Type:     agent.EventThinkStart,
	})

	_ = m.handleAgentEvent(agent.Event{
		TargetID: 1,
		Type:     agent.EventThinkDone,
		Duration: 1 * time.Second,
	})

	if !m.spinning {
		t.Error("expected spinning=true because subtask is still active")
	}
}

func TestHandleAgentEvent_SubTaskStart_StartsSpinner(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true

	cmd := m.handleAgentEvent(agent.Event{
		TargetID: 1,
		Type:     agent.EventSubTaskStart,
		TaskID:   "task-1",
		Message:  "Enumerate shares",
	})

	if !m.spinning {
		t.Error("expected spinning=true after EventSubTaskStart")
	}
	if cmd == nil {
		t.Error("expected non-nil tea.Cmd (spinner.Tick) from EventSubTaskStart")
	}
}

func TestHandleAgentEvent_SubTaskComplete_StopsSpinner(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true

	_ = m.handleAgentEvent(agent.Event{
		TargetID: 1,
		Type:     agent.EventSubTaskStart,
		TaskID:   "task-1",
		Message:  "Scan ports",
	})

	_ = m.handleAgentEvent(agent.Event{
		TargetID: 1,
		Type:     agent.EventSubTaskComplete,
		TaskID:   "task-1",
		Message:  "Scan completed",
	})

	if m.spinning {
		t.Error("expected spinning=false after EventSubTaskComplete with no remaining active blocks")
	}
}

func TestHandleAgentEvent_ThinkStart_AlreadySpinning_NoExtraCmd(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true

	// First ThinkStart — returns spinner.Tick
	cmd1 := m.handleAgentEvent(agent.Event{
		TargetID: 1,
		Type:     agent.EventThinkStart,
	})
	if cmd1 == nil {
		t.Fatal("first ThinkStart should return spinner.Tick")
	}

	// Second ThinkStart while already spinning — should NOT return extra tick
	cmd2 := m.handleAgentEvent(agent.Event{
		TargetID: 1,
		Type:     agent.EventThinkStart,
	})
	if cmd2 != nil {
		t.Error("expected nil cmd when spinner is already running")
	}
}

func TestHandleAgentEvent_CmdDone_ChecksSpinnerState(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true

	// spinning manually set (e.g. thinking block active)
	t1.AddBlock(agent.NewThinkingBlock())
	m.spinning = true

	// CmdDone should not stop spinner if thinking block is still active
	t1.AddBlock(agent.NewCommandBlock("echo test"))
	_ = m.handleAgentEvent(agent.Event{
		TargetID: 1,
		Type:     agent.EventCmdDone,
		ExitCode: 0,
		Duration: 100 * time.Millisecond,
	})

	if !m.spinning {
		t.Error("expected spinning=true because thinking block is still active after CmdDone")
	}
}

// ---------------------------------------------------------------------------
// addTarget — 重複ターゲットガード
// ---------------------------------------------------------------------------

func TestAddTarget_Duplicate(t *testing.T) {
	// Team を作成して TUI に接続
	cfg := agent.TeamConfig{
		Events: make(chan agent.Event, 10),
		Brain:  nil,
		Runner: nil,
	}
	team := agent.NewTeam(cfg)

	m := NewWithTargets(nil)
	m.handleResize(120, 40)
	m.ready = true
	m.team = team

	// 1 回目: 新規ターゲット追加 — 成功するはず
	m.addTarget("10.0.0.1")
	if len(m.targets) != 1 {
		t.Fatalf("expected 1 target after first addTarget, got %d", len(m.targets))
	}
	if m.targets[0].Host != "10.0.0.1" {
		t.Errorf("expected host '10.0.0.1', got %q", m.targets[0].Host)
	}

	// 2 回目: 同じホストで addTarget — 重複なので追加されないはず
	m.addTarget("10.0.0.1")
	if len(m.targets) != 1 {
		t.Errorf("expected 1 target after duplicate addTarget, got %d", len(m.targets))
	}
}

func TestAddTarget_DifferentHosts(t *testing.T) {
	// 異なるホストの場合は両方追加されることを確認
	cfg := agent.TeamConfig{
		Events: make(chan agent.Event, 10),
		Brain:  nil,
		Runner: nil,
	}
	team := agent.NewTeam(cfg)

	m := NewWithTargets(nil)
	m.handleResize(120, 40)
	m.ready = true
	m.team = team

	m.addTarget("10.0.0.1")
	m.addTarget("10.0.0.2")

	if len(m.targets) != 2 {
		t.Fatalf("expected 2 targets for different hosts, got %d", len(m.targets))
	}
	if m.targets[0].Host != "10.0.0.1" {
		t.Errorf("expected first host '10.0.0.1', got %q", m.targets[0].Host)
	}
	if m.targets[1].Host != "10.0.0.2" {
		t.Errorf("expected second host '10.0.0.2', got %q", m.targets[1].Host)
	}
}

func TestHandleAgentEvent_EventAddTarget_Duplicate(t *testing.T) {
	// EventAddTarget 経由で重複ターゲットが追加されないことを確認
	cfg := agent.TeamConfig{
		Events: make(chan agent.Event, 10),
		Brain:  nil,
		Runner: nil,
	}
	team := agent.NewTeam(cfg)

	m := NewWithTargets(nil)
	m.handleResize(120, 40)
	m.ready = true
	m.team = team

	// 最初のターゲットを追加
	m.addTarget("10.0.0.1")
	if len(m.targets) != 1 {
		t.Fatalf("expected 1 target, got %d", len(m.targets))
	}

	// AI が横展開で同じホストを追加しようとする
	_ = m.handleAgentEvent(agent.Event{
		TargetID: m.targets[0].ID,
		Type:     agent.EventAddTarget,
		NewHost:  "10.0.0.1",
	})

	// 重複なので追加されないはず
	if len(m.targets) != 1 {
		t.Errorf("expected 1 target after duplicate EventAddTarget, got %d", len(m.targets))
	}
}

// ---------------------------------------------------------------------------
// handleTargetsCommand -- coverage improvement tests
// ---------------------------------------------------------------------------

// TestHandleTargetsCommand_Empty tests /targets with no targets.
func TestHandleTargetsCommand_Empty(t *testing.T) {
	m := NewWithTargets(nil)
	m.handleResize(120, 40)
	m.ready = true

	m.handleTargetsCommand()

	// No targets -> globalLogs should have a message
	if len(m.globalLogs) == 0 {
		t.Fatal("expected globalLogs to have a message for empty targets")
	}
	found := false
	for _, log := range m.globalLogs {
		if strings.Contains(log, "No targets") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'No targets' message in globalLogs, got: %v", m.globalLogs)
	}
}

// TestHandleTargetsCommand_WithTargets tests /targets shows select UI.
func TestHandleTargetsCommand_WithTargets(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	t2 := agent.NewTarget(2, "10.0.0.2")
	m := NewWithTargets([]*agent.Target{t1, t2})
	m.handleResize(120, 40)
	m.ready = true

	m.handleTargetsCommand()

	if m.inputMode != InputSelect {
		t.Errorf("expected InputSelect mode, got %d", m.inputMode)
	}
	if len(m.selectOptions) != 2 {
		t.Errorf("expected 2 select options, got %d", len(m.selectOptions))
	}
	if m.selectTitle == "" {
		t.Error("expected non-empty selectTitle")
	}
}

// ---------------------------------------------------------------------------
// handleReconTreeCommand -- coverage improvement tests
// ---------------------------------------------------------------------------

// TestHandleReconTreeCommand_NoTarget tests /recontree with no target selected.
func TestHandleReconTreeCommand_NoTarget(t *testing.T) {
	m := NewWithTargets(nil)
	m.handleResize(120, 40)
	m.ready = true

	m.handleReconTreeCommand()

	found := false
	for _, log := range m.globalLogs {
		if strings.Contains(log, "No target selected") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'No target selected' in globalLogs, got: %v", m.globalLogs)
	}
}

// TestHandleReconTreeCommand_NoReconTree tests /recontree when target has no ReconTree.
func TestHandleReconTreeCommand_NoReconTree(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{target})
	m.handleResize(120, 40)
	m.ready = true

	m.handleReconTreeCommand()

	// ReconTree is nil -> should log error to target blocks
	found := false
	for _, b := range target.Blocks {
		if b.Type == agent.BlockSystem && strings.Contains(b.SystemMsg, "No recon tree") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 'No recon tree' system block on target")
	}
}

// TestHandleReconTreeCommand_WithReconTree tests /recontree with valid ReconTree.
func TestHandleReconTreeCommand_WithReconTree(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	rt := agent.NewReconTree("10.0.0.1", 2)
	rt.AddPort(80, "http", "Apache 2.4")
	target.SetReconTree(rt)

	m := NewWithTargets([]*agent.Target{target})
	m.handleResize(120, 40)
	m.ready = true

	m.handleReconTreeCommand()

	// Should log rendered tree to target blocks
	found := false
	for _, b := range target.Blocks {
		if b.Type == agent.BlockSystem && strings.Contains(b.SystemMsg, "80") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected recon tree output containing port 80 in target blocks")
	}
}

// ---------------------------------------------------------------------------
// handleSkipReconCommand -- coverage improvement tests
// ---------------------------------------------------------------------------

// TestHandleSkipReconCommand_NoTarget tests /skip-recon with no target.
func TestHandleSkipReconCommand_NoTarget(t *testing.T) {
	m := NewWithTargets(nil)
	m.handleResize(120, 40)
	m.ready = true

	m.handleSkipReconCommand()

	found := false
	for _, log := range m.globalLogs {
		if strings.Contains(log, "No target selected") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'No target selected' in globalLogs, got: %v", m.globalLogs)
	}
}

// TestHandleSkipReconCommand_NoReconTree tests /skip-recon when no ReconTree.
func TestHandleSkipReconCommand_NoReconTree(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{target})
	m.handleResize(120, 40)
	m.ready = true

	m.handleSkipReconCommand()

	found := false
	for _, b := range target.Blocks {
		if b.Type == agent.BlockSystem && strings.Contains(b.SystemMsg, "No recon tree") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 'No recon tree' system block on target")
	}
}

// TestHandleSkipReconCommand_AlreadyUnlocked tests /skip-recon when already unlocked.
func TestHandleSkipReconCommand_AlreadyUnlocked(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	rt := agent.NewReconTree("10.0.0.1", 2)
	rt.Unlock() // unlock before test
	target.SetReconTree(rt)

	m := NewWithTargets([]*agent.Target{target})
	m.handleResize(120, 40)
	m.ready = true

	m.handleSkipReconCommand()

	found := false
	for _, b := range target.Blocks {
		if b.Type == agent.BlockSystem && strings.Contains(b.SystemMsg, "already unlocked") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 'already unlocked' system block on target")
	}
}

// TestHandleSkipReconCommand_Success tests /skip-recon successfully unlocks.
func TestHandleSkipReconCommand_Success(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	rt := agent.NewReconTree("10.0.0.1", 2)
	rt.AddPort(80, "http", "Apache 2.4") // adds pending tasks
	target.SetReconTree(rt)

	m := NewWithTargets([]*agent.Target{target})
	m.handleResize(120, 40)
	m.ready = true

	if !rt.IsLocked() {
		t.Fatal("precondition: ReconTree should be locked")
	}

	m.handleSkipReconCommand()

	if rt.IsLocked() {
		t.Error("expected ReconTree to be unlocked after /skip-recon")
	}

	found := false
	for _, b := range target.Blocks {
		if b.Type == agent.BlockSystem && strings.Contains(b.SystemMsg, "RECON phase unlocked") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 'RECON phase unlocked' system block on target")
	}
}

// ===========================================================================
// Update() — spinner.TickMsg handling
// ===========================================================================

func TestUpdate_SpinnerTickMsg_WhileSpinning(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true
	m.spinning = true

	result, cmd := m.Update(spinner.TickMsg{})
	rm := result.(Model)

	// viewportDirty should be reset
	if rm.viewportDirty {
		t.Error("expected viewportDirty=false after spinner tick")
	}
	// spinner.Update returns a Cmd to schedule the next tick
	if cmd == nil {
		t.Error("expected non-nil cmd from spinner tick while spinning")
	}
}

func TestUpdate_SpinnerTickMsg_NotSpinning(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true
	m.spinning = false

	_, cmd := m.Update(spinner.TickMsg{})

	// Not spinning -> no cmd returned
	if cmd != nil {
		t.Error("expected nil cmd from spinner tick when not spinning")
	}
}

// ===========================================================================
// Update() — debounceMsg handling
// ===========================================================================

func TestUpdate_DebounceMsg_ViewportDirty(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true
	m.viewportDirty = true

	result, cmd := m.Update(debounceMsg{})
	rm := result.(Model)

	if rm.viewportDirty {
		t.Error("expected viewportDirty=false after debounceMsg flush")
	}
	if cmd != nil {
		t.Error("expected nil cmd from debounceMsg")
	}
}

func TestUpdate_DebounceMsg_NotDirty(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true
	m.viewportDirty = false

	result, cmd := m.Update(debounceMsg{})
	rm := result.(Model)

	if rm.viewportDirty {
		t.Error("viewportDirty should remain false")
	}
	if cmd != nil {
		t.Error("expected nil cmd from debounceMsg when not dirty")
	}
}

// ===========================================================================
// Update() — AgentEventMsg handling
// ===========================================================================

func TestUpdate_AgentEventMsg_WithChannel(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true

	// agentEvents チャネルをセットして、次のイベント待ちコマンドが返ることを確認
	ch := make(chan agent.Event, 1)
	m.agentEvents = ch

	result, cmd := m.Update(AgentEventMsg(agent.Event{
		TargetID: 1,
		Type:     agent.EventLog,
		Source:   agent.SourceSystem,
		Message:  "test message",
	}))
	rm := result.(Model)
	_ = rm

	// cmd should be non-nil (batch of AgentEventCmd for next event)
	if cmd == nil {
		t.Error("expected non-nil cmd (AgentEventCmd) when agentEvents channel is set")
	}

	// Block should have been added
	if len(t1.Blocks) == 0 {
		t.Error("expected at least one block after AgentEventMsg")
	}
}

func TestUpdate_AgentEventMsg_NilChannel(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true
	m.agentEvents = nil // no channel

	_, cmd := m.Update(AgentEventMsg(agent.Event{
		TargetID: 1,
		Type:     agent.EventLog,
		Source:   agent.SourceSystem,
		Message:  "no channel test",
	}))

	// With nil agentEvents, cmd may still be non-nil if spinnerCmd is returned,
	// but AgentEventCmd should not be in the batch.
	// Just ensure no panic.
	_ = cmd
}

func TestUpdate_AgentEventMsg_WithSpinnerCmd(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true

	ch := make(chan agent.Event, 1)
	m.agentEvents = ch

	// ThinkStart event returns a spinner cmd
	result, cmd := m.Update(AgentEventMsg(agent.Event{
		TargetID: 1,
		Type:     agent.EventThinkStart,
	}))
	rm := result.(Model)

	if !rm.spinning {
		t.Error("expected spinning=true after ThinkStart via Update")
	}
	if cmd == nil {
		t.Error("expected non-nil batch cmd (spinner tick + event cmd)")
	}
}

// ===========================================================================
// Update() — KeyMsg in select mode
// ===========================================================================

func TestUpdate_SelectMode_InterceptsKeys(t *testing.T) {
	m := NewWithTargets(nil)
	m.handleResize(120, 40)
	m.ready = true
	m.inputMode = InputSelect
	m.selectOptions = []SelectOption{
		{Label: "Option A", Value: "a"},
		{Label: "Option B", Value: "b"},
	}
	m.selectIndex = 0

	// Down arrow should move selection
	result, cmd := m.Update(tea.KeyMsg{Type: tea.KeyDown})
	rm := result.(Model)

	if cmd != nil {
		t.Error("expected nil cmd from select mode key")
	}
	if rm.selectIndex != 1 {
		t.Errorf("expected selectIndex=1 after down arrow, got %d", rm.selectIndex)
	}
}

func TestUpdate_SelectMode_Enter(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true

	callbackCalled := false
	m.showSelect("Test:", []SelectOption{
		{Label: "Option A", Value: "a"},
	}, func(model *Model, value string) {
		callbackCalled = true
	})

	// Enter to confirm selection
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	rm := result.(Model)

	if rm.inputMode != InputNormal {
		t.Errorf("expected InputNormal after select confirm, got %d", rm.inputMode)
	}
	if !callbackCalled {
		t.Error("expected callback to be called on Enter")
	}
}

func TestUpdate_SelectMode_Escape(t *testing.T) {
	m := NewWithTargets(nil)
	m.handleResize(120, 40)
	m.ready = true
	m.showSelect("Test:", []SelectOption{
		{Label: "Option A", Value: "a"},
	}, func(model *Model, value string) {
		t.Error("callback should not be called on Escape")
	})

	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyEscape})
	rm := result.(Model)

	if rm.inputMode != InputNormal {
		t.Errorf("expected InputNormal after Escape, got %d", rm.inputMode)
	}
}

// ===========================================================================
// Update() — Ctrl+O toggles log folding
// ===========================================================================

func TestUpdate_CtrlO_TogglesLogFolding(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true
	m.logsExpanded = false

	result, cmd := m.Update(tea.KeyMsg{Type: tea.KeyCtrlO})
	rm := result.(Model)

	if cmd != nil {
		t.Error("expected nil cmd from Ctrl+O")
	}
	if !rm.logsExpanded {
		t.Error("expected logsExpanded=true after Ctrl+O toggle")
	}

	// Toggle back
	result2, _ := rm.Update(tea.KeyMsg{Type: tea.KeyCtrlO})
	rm2 := result2.(Model)
	if rm2.logsExpanded {
		t.Error("expected logsExpanded=false after second Ctrl+O toggle")
	}
}

// ===========================================================================
// Update() — Proposal approval keys (y/n/e)
// ===========================================================================

func TestUpdate_ProposalApprove_Y(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true

	approveCh := make(chan bool, 1)
	m.agentApproveMap[t1.ID] = approveCh

	t1.SetProposal(&agent.Proposal{
		Description: "Run nmap scan",
		Tool:        "nmap",
		Args:        []string{"-sV", "10.0.0.1"},
	})

	result, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'y'}})
	rm := result.(Model)

	if cmd != nil {
		t.Error("expected nil cmd from Y approval")
	}
	_ = rm

	// Proposal should be cleared
	if t1.GetProposal() != nil {
		t.Error("expected proposal to be cleared after Y")
	}

	// Approve signal should be sent
	select {
	case approved := <-approveCh:
		if !approved {
			t.Error("expected true on approve channel")
		}
	default:
		t.Error("expected a value on approve channel")
	}
}

func TestUpdate_ProposalReject_N(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true

	approveCh := make(chan bool, 1)
	m.agentApproveMap[t1.ID] = approveCh

	t1.SetProposal(&agent.Proposal{
		Description: "Run exploit",
		Tool:        "msfconsole",
		Args:        []string{"-x", "exploit"},
	})

	result, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'n'}})
	rm := result.(Model)
	_ = rm

	if cmd != nil {
		t.Error("expected nil cmd from N rejection")
	}

	// Proposal should be cleared
	if t1.GetProposal() != nil {
		t.Error("expected proposal to be cleared after N")
	}

	// Reject signal should be sent
	select {
	case approved := <-approveCh:
		if approved {
			t.Error("expected false on approve channel")
		}
	default:
		t.Error("expected a value on approve channel")
	}
}

func TestUpdate_ProposalEdit_E(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true
	m.focus = FocusViewport // start from viewport focus

	t1.SetProposal(&agent.Proposal{
		Description: "Run scan",
		Tool:        "nmap",
		Args:        []string{"-sV", "target"},
	})

	result, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'e'}})
	rm := result.(Model)

	if cmd != nil {
		t.Error("expected nil cmd from E edit")
	}

	// Focus should switch to input
	if rm.focus != FocusInput {
		t.Errorf("expected FocusInput after E, got %d", rm.focus)
	}

	// Input should be populated with the proposal command
	inputVal := rm.input.Value()
	if !strings.Contains(inputVal, "nmap") {
		t.Errorf("expected input to contain 'nmap', got %q", inputVal)
	}
	if !strings.Contains(inputVal, "-sV") {
		t.Errorf("expected input to contain '-sV', got %q", inputVal)
	}
}

func TestUpdate_ProposalApprove_NoChannelInMap(t *testing.T) {
	// Proposal approve when no channel in agentApproveMap — should not panic
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true
	// agentApproveMap has no entry for t1.ID

	t1.SetProposal(&agent.Proposal{
		Description: "Run test",
		Tool:        "echo",
		Args:        []string{"hello"},
	})

	// Should not panic
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'y'}})
	rm := result.(Model)
	_ = rm

	// Proposal should still be cleared
	if t1.GetProposal() != nil {
		t.Error("expected proposal to be cleared even without channel")
	}
}

func TestUpdate_ProposalReject_NoChannelInMap(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true

	t1.SetProposal(&agent.Proposal{
		Description: "Run test",
		Tool:        "echo",
		Args:        []string{"hello"},
	})

	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'N'}})
	rm := result.(Model)
	_ = rm

	if t1.GetProposal() != nil {
		t.Error("expected proposal to be cleared after N even without channel")
	}
}

// ===========================================================================
// Update() — FocusViewport key handling (viewport scrolling)
// ===========================================================================

func TestUpdate_ViewportFocus_PassesKeysToViewport(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true
	m.focus = FocusViewport

	// Send an arrow key while viewport is focused — should not panic
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyUp})
	rm := result.(Model)

	if rm.focus != FocusViewport {
		t.Errorf("expected FocusViewport to be maintained, got %d", rm.focus)
	}
}

// ===========================================================================
// Update() — FocusInput enter key calls submitInput
// ===========================================================================

func TestUpdate_FocusInput_EnterSubmits(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true
	m.focus = FocusInput
	m.input.SetValue("test input text")

	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	rm := result.(Model)

	// Input should be cleared after submit
	if rm.input.Value() != "" {
		t.Errorf("expected input to be cleared after Enter, got %q", rm.input.Value())
	}

	// Block should be added
	if len(t1.Blocks) == 0 {
		t.Error("expected at least one block after Enter submit")
	}
}

func TestUpdate_FocusInput_OtherKeys_PassToTextarea(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true
	m.focus = FocusInput

	// Type a regular character
	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'a'}})
	rm := result.(Model)

	// The character should be appended to the input
	if !strings.Contains(rm.input.Value(), "a") {
		t.Errorf("expected input to contain 'a', got %q", rm.input.Value())
	}
}

// ===========================================================================
// Update() — WindowSizeMsg edge cases
// ===========================================================================

func TestUpdate_WindowSizeMsg_SmallTerminal(t *testing.T) {
	m := NewWithTargets(nil)

	// Very small terminal — handleResize should clamp to minimums
	result, cmd := m.Update(tea.WindowSizeMsg{Width: 15, Height: 8})
	rm := result.(Model)

	if cmd != nil {
		t.Error("expected nil cmd from WindowSizeMsg")
	}
	if !rm.ready {
		t.Error("expected ready=true")
	}
	if rm.width != 15 {
		t.Errorf("expected width=15, got %d", rm.width)
	}
	if rm.height != 8 {
		t.Errorf("expected height=8, got %d", rm.height)
	}
}

func TestUpdate_WindowSizeMsg_AlreadyReady(t *testing.T) {
	m := NewWithTargets(nil)
	// First resize
	result, _ := m.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	m = result.(Model)

	// Second resize — already ready, so viewport dimensions should be updated (not recreated)
	result, _ = m.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	rm := result.(Model)

	if rm.width != 120 {
		t.Errorf("expected width=120, got %d", rm.width)
	}
	if rm.height != 40 {
		t.Errorf("expected height=40, got %d", rm.height)
	}
}

// ===========================================================================
// handleResize — edge cases for small sizes
// ===========================================================================

func TestHandleResize_VerySmallWidth(t *testing.T) {
	m := NewWithTargets(nil)
	m.handleResize(5, 30)

	// vpW = 5 - 4 = 1, should be clamped to 10
	if m.viewport.Width < 10 {
		t.Errorf("expected viewport width >= 10 for very small terminal, got %d", m.viewport.Width)
	}
}

func TestHandleResize_VerySmallHeight(t *testing.T) {
	m := NewWithTargets(nil)
	m.handleResize(80, 5)

	// paneH should be clamped to minimum 4
	// This ensures viewport doesn't get negative height
	if m.viewport.Height < 2 {
		t.Errorf("expected viewport height >= 2, got %d", m.viewport.Height)
	}
}

// ===========================================================================
// submitInput — slash command routing
// ===========================================================================

func TestSubmitInput_TargetsRouting(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	t2 := agent.NewTarget(2, "10.0.0.2")
	m := NewWithTargets([]*agent.Target{t1, t2})
	m.handleResize(120, 40)
	m.ready = true
	m.input.SetValue("/targets")

	m.submitInput()

	if m.inputMode != InputSelect {
		t.Errorf("expected InputSelect mode after /targets, got %d", m.inputMode)
	}
}

func TestSubmitInput_ReconTreeRouting(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{target})
	m.handleResize(120, 40)
	m.ready = true
	m.input.SetValue("/recontree")

	blocksBefore := len(target.Blocks)
	m.submitInput()

	// Should have logged "No recon tree available" since target has no ReconTree
	if len(target.Blocks) <= blocksBefore {
		t.Error("expected a system block for /recontree with no recon tree")
	}
}

func TestSubmitInput_SkipReconRouting(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{target})
	m.handleResize(120, 40)
	m.ready = true
	m.input.SetValue("/skip-recon")

	blocksBefore := len(target.Blocks)
	m.submitInput()

	// Should have logged "No recon tree available" since target has no ReconTree
	if len(target.Blocks) <= blocksBefore {
		t.Error("expected a system block for /skip-recon with no recon tree")
	}
}

func TestSubmitInput_TargetCommand(t *testing.T) {
	cfg := agent.TeamConfig{
		Events: make(chan agent.Event, 10),
		Brain:  nil,
		Runner: nil,
	}
	team := agent.NewTeam(cfg)

	m := NewWithTargets(nil)
	m.handleResize(120, 40)
	m.ready = true
	m.team = team
	m.input.SetValue("/target 10.0.0.5")

	m.submitInput()

	if len(m.targets) != 1 {
		t.Fatalf("expected 1 target after /target command, got %d", len(m.targets))
	}
	if m.targets[0].Host != "10.0.0.5" {
		t.Errorf("expected host '10.0.0.5', got %q", m.targets[0].Host)
	}
}

func TestSubmitInput_BareIP_WithTeam(t *testing.T) {
	cfg := agent.TeamConfig{
		Events: make(chan agent.Event, 10),
		Brain:  nil,
		Runner: nil,
	}
	team := agent.NewTeam(cfg)

	m := NewWithTargets(nil)
	m.handleResize(120, 40)
	m.ready = true
	m.team = team
	m.input.SetValue("10.0.0.99")

	m.submitInput()

	if len(m.targets) != 1 {
		t.Fatalf("expected 1 target after bare IP, got %d", len(m.targets))
	}
	if m.targets[0].Host != "10.0.0.99" {
		t.Errorf("expected host '10.0.0.99', got %q", m.targets[0].Host)
	}
}

func TestSubmitInput_NaturalLanguageHost_WithTeam(t *testing.T) {
	cfg := agent.TeamConfig{
		Events: make(chan agent.Event, 10),
		Brain:  nil,
		Runner: nil,
	}
	team := agent.NewTeam(cfg)

	m := NewWithTargets(nil)
	m.handleResize(120, 40)
	m.ready = true
	m.team = team
	m.input.SetValue("192.168.1.1をスキャンして")

	m.submitInput()

	// Should extract host and create target
	if len(m.targets) != 1 {
		t.Fatalf("expected 1 target from natural language, got %d", len(m.targets))
	}
	if m.targets[0].Host != "192.168.1.1" {
		t.Errorf("expected host '192.168.1.1', got %q", m.targets[0].Host)
	}
}

func TestSubmitInput_NaturalLanguageDomain_WithTeam(t *testing.T) {
	cfg := agent.TeamConfig{
		Events: make(chan agent.Event, 10),
		Brain:  nil,
		Runner: nil,
	}
	team := agent.NewTeam(cfg)

	m := NewWithTargets(nil)
	m.handleResize(120, 40)
	m.ready = true
	m.team = team
	m.input.SetValue("eighteen.htbを攻撃して")

	m.submitInput()

	if len(m.targets) != 1 {
		t.Fatalf("expected 1 target from domain extraction, got %d", len(m.targets))
	}
	if m.targets[0].Host != "eighteen.htb" {
		t.Errorf("expected host 'eighteen.htb', got %q", m.targets[0].Host)
	}
}

func TestSubmitInput_NaturalLanguageHost_WithRemainingMsg(t *testing.T) {
	cfg := agent.TeamConfig{
		Events: make(chan agent.Event, 10),
		Brain:  nil,
		Runner: nil,
	}
	team := agent.NewTeam(cfg)

	m := NewWithTargets(nil)
	m.handleResize(120, 40)
	m.ready = true
	m.team = team

	// Set up user msg channel so we can verify message routing
	// Note: addTarget will create the channel mapping when team is used
	m.input.SetValue("scan 10.0.0.50 for open ports")

	m.submitInput()

	if len(m.targets) != 1 {
		t.Fatalf("expected 1 target, got %d", len(m.targets))
	}
	if m.targets[0].Host != "10.0.0.50" {
		t.Errorf("expected host '10.0.0.50', got %q", m.targets[0].Host)
	}

	// Original full text should be logged as a user block
	found := false
	for _, b := range m.targets[0].Blocks {
		if b.Type == agent.BlockUserInput && strings.Contains(b.UserText, "scan 10.0.0.50 for open ports") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected original full text to be logged as user block")
	}
}

func TestSubmitInput_NaturalLanguageHost_ExistingTargets_NoExtract(t *testing.T) {
	// When targets already exist, natural language extraction should NOT happen
	t1 := agent.NewTarget(1, "10.0.0.1")
	cfg := agent.TeamConfig{
		Events: make(chan agent.Event, 10),
		Brain:  nil,
		Runner: nil,
	}
	team := agent.NewTeam(cfg)

	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true
	m.team = team
	m.input.SetValue("scan 192.168.1.1 please")

	targetsBefore := len(m.targets)
	m.submitInput()

	// Should NOT extract host because targets already exist
	if len(m.targets) != targetsBefore {
		t.Errorf("expected no new targets when targets already exist, got %d", len(m.targets))
	}
}

func TestSubmitInput_SendsToAgentChannel(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true

	userMsgCh := make(chan string, 1)
	m.agentUserMsgMap[t1.ID] = userMsgCh
	m.input.SetValue("run nmap -sV")

	m.submitInput()

	// Message should be sent to agent channel
	select {
	case msg := <-userMsgCh:
		if msg != "run nmap -sV" {
			t.Errorf("expected 'run nmap -sV' on channel, got %q", msg)
		}
	default:
		t.Error("expected message on userMsg channel")
	}
}

func TestSubmitInput_NoActiveTarget_NoChannel(t *testing.T) {
	// When no active target and no agent channel, should not panic
	m := NewWithTargets(nil)
	m.handleResize(120, 40)
	m.ready = true
	m.input.SetValue("some text without target")

	// Should not panic — no target, no channel, just no-op
	m.submitInput()
}

func TestSubmitInput_ApproveRouting_NoRunner(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true
	m.Runner = nil
	m.input.SetValue("/approve")

	blocksBefore := len(t1.Blocks)
	m.submitInput()

	// Without runner, should log "not available"
	if len(t1.Blocks) <= blocksBefore {
		t.Error("expected system block for /approve without runner")
	}
	found := false
	for _, b := range t1.Blocks {
		if b.Type == agent.BlockSystem && strings.Contains(b.SystemMsg, "not available") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 'not available' message for /approve without runner")
	}
}

// ===========================================================================
// switchModel — all branches
// ===========================================================================

func TestSwitchModel_NilBrainFactory(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true
	m.BrainFactory = nil

	m.switchModel(brain.ProviderAnthropic, "claude-sonnet-4-6")

	// Should log "not available" message
	found := false
	for _, b := range t1.Blocks {
		if b.Type == agent.BlockSystem && strings.Contains(b.SystemMsg, "not available") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 'not available' message for nil BrainFactory")
	}
}

func TestSwitchModel_FactoryError(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true
	m.BrainFactory = func(hint brain.ConfigHint) (brain.Brain, error) {
		return nil, errors.New("connection refused")
	}

	m.switchModel(brain.ProviderAnthropic, "claude-sonnet-4-6")

	found := false
	for _, b := range t1.Blocks {
		if b.Type == agent.BlockSystem && strings.Contains(b.SystemMsg, "Failed to switch model") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 'Failed to switch model' message on factory error")
	}
}

func TestSwitchModel_Success_WithTeam(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	cfg := agent.TeamConfig{
		Events: make(chan agent.Event, 10),
		Brain:  nil,
		Runner: nil,
	}
	team := agent.NewTeam(cfg)

	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true
	m.team = team
	m.BrainFactory = func(hint brain.ConfigHint) (brain.Brain, error) {
		return nil, nil // nil brain is ok for test
	}

	m.switchModel(brain.ProviderAnthropic, "claude-sonnet-4-6")

	if m.CurrentProvider != "anthropic" {
		t.Errorf("expected CurrentProvider 'anthropic', got %q", m.CurrentProvider)
	}
	if m.CurrentModel != "claude-sonnet-4-6" {
		t.Errorf("expected CurrentModel 'claude-sonnet-4-6', got %q", m.CurrentModel)
	}

	found := false
	for _, b := range t1.Blocks {
		if b.Type == agent.BlockSystem && strings.Contains(b.SystemMsg, "Switched to anthropic/claude-sonnet-4-6") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 'Switched to' message with model name")
	}
}

func TestSwitchModel_Success_NoModel(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true
	m.BrainFactory = func(hint brain.ConfigHint) (brain.Brain, error) {
		return nil, nil
	}

	m.switchModel(brain.ProviderOllama, "")

	if m.CurrentProvider != "ollama" {
		t.Errorf("expected CurrentProvider 'ollama', got %q", m.CurrentProvider)
	}
	if m.CurrentModel != "" {
		t.Errorf("expected empty CurrentModel, got %q", m.CurrentModel)
	}

	found := false
	for _, b := range t1.Blocks {
		if b.Type == agent.BlockSystem && strings.Contains(b.SystemMsg, "Switched to ollama") && !strings.Contains(b.SystemMsg, "/") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 'Switched to ollama' message without model suffix")
	}
}

func TestSwitchModel_Success_NilTeam(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true
	m.team = nil
	m.BrainFactory = func(hint brain.ConfigHint) (brain.Brain, error) {
		return nil, nil
	}

	// Should not panic when team is nil
	m.switchModel(brain.ProviderAnthropic, "claude-sonnet-4-6")

	if m.CurrentProvider != "anthropic" {
		t.Errorf("expected CurrentProvider 'anthropic', got %q", m.CurrentProvider)
	}
}

// ===========================================================================
// handleTargetsCommand — callback execution
// ===========================================================================

func TestHandleTargetsCommand_CallbackSelectsTarget(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	t2 := agent.NewTarget(2, "10.0.0.2")
	m := NewWithTargets([]*agent.Target{t1, t2})
	m.handleResize(120, 40)
	m.ready = true
	m.selected = 0

	m.handleTargetsCommand()

	if m.inputMode != InputSelect {
		t.Fatalf("expected InputSelect mode, got %d", m.inputMode)
	}

	// Simulate selecting the second target (index 1)
	m.selectIndex = 1

	// Invoke callback directly (simulating Enter press)
	if m.selectCallback != nil {
		cb := m.selectCallback
		value := m.selectOptions[m.selectIndex].Value
		m.inputMode = InputNormal
		m.selectOptions = nil
		m.selectCallback = nil
		cb(&m, value)
	}

	if m.selected != 1 {
		t.Errorf("expected selected=1, got %d", m.selected)
	}
}

func TestHandleTargetsCommand_CallbackInvalidValue(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true

	m.handleTargetsCommand()

	if m.selectCallback == nil {
		t.Fatal("expected selectCallback to be set")
	}

	// Invoke callback with invalid (non-numeric) value
	m.selectCallback(&m, "invalid")

	// Should not change selection
	if m.selected != 0 {
		t.Errorf("expected selected=0 unchanged, got %d", m.selected)
	}
}

func TestHandleTargetsCommand_CallbackOutOfRange(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true

	m.handleTargetsCommand()

	if m.selectCallback == nil {
		t.Fatal("expected selectCallback to be set")
	}

	// Invoke callback with out-of-range index
	m.selectCallback(&m, "99")

	// Should not change selection
	if m.selected != 0 {
		t.Errorf("expected selected=0 unchanged after out-of-range callback, got %d", m.selected)
	}
}

// ===========================================================================
// modelsForProvider — all providers
// ===========================================================================

func TestModelsForProvider_Anthropic(t *testing.T) {
	models := modelsForProvider(brain.ProviderAnthropic)
	if len(models) == 0 {
		t.Fatal("expected models for Anthropic provider")
	}
	// Check that claude-sonnet-4-6 is in the list
	found := false
	for _, m := range models {
		if strings.Contains(m.Value, "claude-sonnet-4-6") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected claude-sonnet-4-6 in Anthropic models")
	}
}

func TestModelsForProvider_OpenAI(t *testing.T) {
	models := modelsForProvider(brain.ProviderOpenAI)
	if len(models) == 0 {
		t.Fatal("expected models for OpenAI provider")
	}
	found := false
	for _, m := range models {
		if m.Value == "gpt-4o" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected gpt-4o in OpenAI models")
	}
}

func TestModelsForProvider_Ollama(t *testing.T) {
	models := modelsForProvider(brain.ProviderOllama)
	if len(models) == 0 {
		t.Fatal("expected models for Ollama provider")
	}
	found := false
	for _, m := range models {
		if m.Value == "llama3.2" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected llama3.2 in Ollama models")
	}
}

func TestModelsForProvider_Unknown(t *testing.T) {
	models := modelsForProvider(brain.Provider("unknown"))
	if models != nil {
		t.Errorf("expected nil for unknown provider, got %v", models)
	}
}

// ===========================================================================
// handleAgentEvent — EventLog with SourceTool and SourceUser
// ===========================================================================

func TestHandleAgentEvent_EventLog_SourceTool_NewBlock(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true

	blocksBefore := len(t1.Blocks)
	_ = m.handleAgentEvent(agent.Event{
		TargetID: 1,
		Type:     agent.EventLog,
		Source:   agent.SourceTool,
		Message:  "Starting nmap scan",
	})

	if len(t1.Blocks) != blocksBefore+1 {
		t.Fatalf("expected 1 new block for tool log, got %d", len(t1.Blocks)-blocksBefore)
	}
	lastBlock := t1.Blocks[len(t1.Blocks)-1]
	if lastBlock.Type != agent.BlockCommand {
		t.Errorf("expected BlockCommand for tool log, got %d", lastBlock.Type)
	}
}

func TestHandleAgentEvent_EventLog_SourceTool_AppendToExisting(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true

	// Add an incomplete command block
	t1.AddBlock(agent.NewCommandBlock("nmap"))

	blocksBefore := len(t1.Blocks)
	_ = m.handleAgentEvent(agent.Event{
		TargetID: 1,
		Type:     agent.EventLog,
		Source:   agent.SourceTool,
		Message:  "80/tcp open http",
	})

	// Should append to existing block, not create a new one
	if len(t1.Blocks) != blocksBefore {
		t.Errorf("expected no new block (append to existing), got %d new", len(t1.Blocks)-blocksBefore)
	}
	lastBlock := t1.LastBlock()
	if len(lastBlock.Output) != 1 || lastBlock.Output[0] != "80/tcp open http" {
		t.Errorf("expected output to be appended, got %v", lastBlock.Output)
	}
}

func TestHandleAgentEvent_EventLog_SourceUser(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true

	blocksBefore := len(t1.Blocks)
	_ = m.handleAgentEvent(agent.Event{
		TargetID: 1,
		Type:     agent.EventLog,
		Source:   agent.SourceUser,
		Message:  "User input message",
	})

	if len(t1.Blocks) != blocksBefore+1 {
		t.Fatalf("expected 1 new block, got %d", len(t1.Blocks)-blocksBefore)
	}
	lastBlock := t1.Blocks[len(t1.Blocks)-1]
	if lastBlock.Type != agent.BlockUserInput {
		t.Errorf("expected BlockUserInput, got %d", lastBlock.Type)
	}
	if lastBlock.UserText != "User input message" {
		t.Errorf("expected 'User input message', got %q", lastBlock.UserText)
	}
}

// ===========================================================================
// handleAgentEvent — EventSubTaskLog
// ===========================================================================

func TestHandleAgentEvent_EventSubTaskLog(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true

	blocksBefore := len(t1.Blocks)
	_ = m.handleAgentEvent(agent.Event{
		TargetID: 1,
		Type:     agent.EventSubTaskLog,
		TaskID:   "task-1",
		Message:  "subtask internal log",
	})

	// EventSubTaskLog should NOT add any blocks
	if len(t1.Blocks) != blocksBefore {
		t.Errorf("expected no new blocks for SubTaskLog, got %d new", len(t1.Blocks)-blocksBefore)
	}
}

// ===========================================================================
// handleAgentEvent — EventCmdOutput debounce behavior
// ===========================================================================

func TestHandleAgentEvent_EventCmdOutput_Debounce_NotSpinning(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true
	m.spinning = false

	t1.AddBlock(agent.NewCommandBlock("echo test"))

	cmd := m.handleAgentEvent(agent.Event{
		TargetID:   1,
		Type:       agent.EventCmdOutput,
		OutputLine: "output line",
	})

	if !m.viewportDirty {
		t.Error("expected viewportDirty=true after CmdOutput")
	}
	// When not spinning, debounce timer should be returned
	if cmd == nil {
		t.Error("expected non-nil debounce cmd when not spinning")
	}
}

func TestHandleAgentEvent_EventCmdOutput_Debounce_WhileSpinning(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true
	m.spinning = true

	t1.AddBlock(agent.NewCommandBlock("echo test"))

	cmd := m.handleAgentEvent(agent.Event{
		TargetID:   1,
		Type:       agent.EventCmdOutput,
		OutputLine: "output while spinning",
	})

	if !m.viewportDirty {
		t.Error("expected viewportDirty=true after CmdOutput")
	}
	// When spinning, next spinner tick will flush — no debounce cmd needed
	if cmd != nil {
		t.Error("expected nil cmd (debounce deferred to spinner tick) when spinning")
	}
}

// ===========================================================================
// handleAgentEvent — EventAddTarget with empty host
// ===========================================================================

func TestHandleAgentEvent_EventAddTarget_EmptyHost(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	cfg := agent.TeamConfig{
		Events: make(chan agent.Event, 10),
		Brain:  nil,
		Runner: nil,
	}
	team := agent.NewTeam(cfg)

	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true
	m.team = team

	targetsBefore := len(m.targets)
	_ = m.handleAgentEvent(agent.Event{
		TargetID: 1,
		Type:     agent.EventAddTarget,
		NewHost:  "", // empty host
	})

	if len(m.targets) != targetsBefore {
		t.Errorf("expected no new target for empty host, got %d", len(m.targets))
	}
}

// ===========================================================================
// handleAgentEvent — non-active target event (no viewport update)
// ===========================================================================

func TestHandleAgentEvent_NonActiveTarget_NoViewportUpdate(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	t2 := agent.NewTarget(2, "10.0.0.2")
	m := NewWithTargets([]*agent.Target{t1, t2})
	m.handleResize(120, 40)
	m.ready = true
	m.selected = 0 // t1 is active

	// Event for t2 — needsViewportUpdate is false
	_ = m.handleAgentEvent(agent.Event{
		TargetID:   2,
		Type:       agent.EventCmdOutput,
		OutputLine: "output for t2",
	})

	// viewportDirty should NOT be set for non-active target's CmdOutput
	if m.viewportDirty {
		t.Error("expected viewportDirty=false for non-active target event")
	}
}

// ===========================================================================
// renderStatusBar — model info branches
// ===========================================================================

func TestRenderStatusBar_ProviderOnly(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true
	m.CurrentProvider = "anthropic"
	m.CurrentModel = "" // empty model

	bar := m.renderStatusBar()
	if !strings.Contains(bar, "Model: anthropic") {
		t.Error("expected 'Model: anthropic' in status bar when only provider is set")
	}
}

func TestRenderStatusBar_ProviderAndModel(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true
	m.CurrentProvider = "anthropic"
	m.CurrentModel = "claude-sonnet-4-6"

	bar := m.renderStatusBar()
	if !strings.Contains(bar, "Model: anthropic/claude-sonnet-4-6") {
		t.Error("expected 'Model: anthropic/claude-sonnet-4-6' in status bar")
	}
}

func TestRenderStatusBar_NoProvider(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true
	m.CurrentProvider = ""
	m.CurrentModel = ""

	bar := m.renderStatusBar()
	if strings.Contains(bar, "Model:") {
		t.Error("expected no 'Model:' in status bar when provider is empty")
	}
}

func TestRenderStatusBar_NoTarget_ShowsMessage(t *testing.T) {
	m := NewWithTargets(nil)
	m.handleResize(120, 40)
	m.ready = true

	bar := m.renderStatusBar()
	if !strings.Contains(bar, "No target selected") {
		t.Error("expected 'No target selected' in status bar when no targets")
	}
}

// ===========================================================================
// handleModelCommand — no providers detected
// ===========================================================================

func TestHandleModelCommand_NoProviders_ViaSubmit(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "")
	t.Setenv("ANTHROPIC_AUTH_TOKEN", "")
	t.Setenv("OLLAMA_BASE_URL", "")

	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true
	m.input.SetValue("/model")

	m.submitInput()

	// Should log "No providers detected"
	found := false
	for _, b := range t1.Blocks {
		if b.Type == agent.BlockSystem && strings.Contains(b.SystemMsg, "No providers detected") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 'No providers detected' message")
	}
}

func TestHandleModelCommand_WithProvider_ShowsSelect(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "sk-test")
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "")
	t.Setenv("ANTHROPIC_AUTH_TOKEN", "")
	t.Setenv("OLLAMA_BASE_URL", "")

	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true

	m.handleModelCommand("")

	if m.inputMode != InputSelect {
		t.Errorf("expected InputSelect after /model, got %d", m.inputMode)
	}
	if len(m.selectOptions) == 0 {
		t.Error("expected at least one select option")
	}
}

func TestHandleModelCommand_ProviderCallback_ShowsModelSelect(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "sk-test")
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "")
	t.Setenv("ANTHROPIC_AUTH_TOKEN", "")
	t.Setenv("OLLAMA_BASE_URL", "")

	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true

	m.handleModelCommand("")

	// Execute the provider selection callback (select "anthropic")
	if m.selectCallback != nil {
		m.selectCallback(&m, "anthropic")
	}

	// Should now show model selection
	if m.inputMode != InputSelect {
		t.Errorf("expected InputSelect for model selection, got %d", m.inputMode)
	}
	if len(m.selectOptions) == 0 {
		t.Error("expected model options for anthropic")
	}
}

func TestHandleModelCommand_ProviderCallback_UnknownProvider(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "sk-test")
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "")
	t.Setenv("ANTHROPIC_AUTH_TOKEN", "")
	t.Setenv("OLLAMA_BASE_URL", "")

	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true
	m.BrainFactory = func(hint brain.ConfigHint) (brain.Brain, error) {
		return nil, nil
	}

	m.handleModelCommand("")

	// Execute the provider selection callback with an unknown provider
	// (modelsForProvider returns nil → switchModel is called directly)
	if m.selectCallback != nil {
		m.selectCallback(&m, "unknown_provider")
	}

	// Should have called switchModel with empty model (no model list for unknown provider)
	// CurrentProvider should be set if BrainFactory succeeded
	if m.CurrentProvider != "unknown_provider" {
		t.Errorf("expected CurrentProvider 'unknown_provider', got %q", m.CurrentProvider)
	}
}

// ===========================================================================
// handleApproveCommand — callback execution
// ===========================================================================

func TestHandleApproveCommand_CallbackOn(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true
	runner := tools.NewCommandRunner(tools.NewRegistry(), tools.NewBlacklist(nil), tools.NewLogStore())
	m.Runner = runner

	m.handleApproveCommand("/approve")

	if m.inputMode != InputSelect {
		t.Fatalf("expected InputSelect, got %d", m.inputMode)
	}

	// Execute callback with "on"
	if m.selectCallback != nil {
		m.selectCallback(&m, "on")
	}

	if !runner.AutoApprove() {
		t.Error("expected AutoApprove=true after selecting ON")
	}
}

func TestHandleApproveCommand_CallbackOff(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true
	runner := tools.NewCommandRunner(tools.NewRegistry(), tools.NewBlacklist(nil), tools.NewLogStore())
	runner.SetAutoApprove(true)
	m.Runner = runner

	m.handleApproveCommand("/approve")

	// Execute callback with "off"
	if m.selectCallback != nil {
		m.selectCallback(&m, "off")
	}

	if runner.AutoApprove() {
		t.Error("expected AutoApprove=false after selecting OFF")
	}
}

func TestHandleApproveCommand_CallbackNilRunner(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true
	runner := tools.NewCommandRunner(tools.NewRegistry(), tools.NewBlacklist(nil), tools.NewLogStore())
	m.Runner = runner

	m.handleApproveCommand("/approve")

	// Set Runner to nil before callback (edge case)
	m.Runner = nil
	if m.selectCallback != nil {
		// Should not panic
		m.selectCallback(&m, "on")
	}
}

// ===========================================================================
// logSystem — with and without active target
// ===========================================================================

func TestLogSystem_NoActiveTarget(t *testing.T) {
	m := NewWithTargets(nil)
	m.handleResize(120, 40)
	m.ready = true

	m.logSystem("test global log")

	if len(m.globalLogs) != 1 {
		t.Fatalf("expected 1 global log, got %d", len(m.globalLogs))
	}
	if m.globalLogs[0] != "test global log" {
		t.Errorf("expected 'test global log', got %q", m.globalLogs[0])
	}
}

func TestLogSystem_WithActiveTarget(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true

	blocksBefore := len(t1.Blocks)
	m.logSystem("target log message")

	if len(t1.Blocks) != blocksBefore+1 {
		t.Fatalf("expected 1 new block, got %d", len(t1.Blocks)-blocksBefore)
	}
	lastBlock := t1.Blocks[len(t1.Blocks)-1]
	if lastBlock.Type != agent.BlockSystem {
		t.Errorf("expected BlockSystem, got %d", lastBlock.Type)
	}
	if lastBlock.SystemMsg != "target log message" {
		t.Errorf("expected 'target log message', got %q", lastBlock.SystemMsg)
	}
}

// ===========================================================================
// AgentEventCmd — basic functionality
// ===========================================================================

func TestAgentEventCmd_ReturnsCmd(t *testing.T) {
	ch := make(chan agent.Event, 1)
	cmd := AgentEventCmd(ch)
	if cmd == nil {
		t.Fatal("expected non-nil cmd from AgentEventCmd")
	}

	// Push an event to the channel so the cmd can resolve
	ch <- agent.Event{
		TargetID: 1,
		Type:     agent.EventLog,
		Source:   agent.SourceSystem,
		Message:  "test",
	}

	// Execute the cmd and verify it returns an AgentEventMsg
	msg := cmd()
	eventMsg, ok := msg.(AgentEventMsg)
	if !ok {
		t.Fatalf("expected AgentEventMsg, got %T", msg)
	}
	if agent.Event(eventMsg).Message != "test" {
		t.Errorf("expected message 'test', got %q", agent.Event(eventMsg).Message)
	}
}

// ===========================================================================
// Update() — unknown message type (default case)
// ===========================================================================

func TestUpdate_UnknownMsgType(t *testing.T) {
	m := NewWithTargets(nil)
	m.handleResize(120, 40)
	m.ready = true

	// Send a custom message type that is not handled
	type customMsg struct{}
	result, cmd := m.Update(customMsg{})
	rm := result.(Model)
	_ = rm

	// Should not panic, cmd should be tea.Batch of empty cmds
	if cmd != nil {
		// tea.Batch(nil...) may return non-nil, but it should be safe
		_ = cmd
	}
}

// ===========================================================================
// handleSelectKey — up/down boundary checks
// ===========================================================================

func TestHandleSelectKey_UpAtTop(t *testing.T) {
	m := NewWithTargets(nil)
	m.showSelect("Test:", []SelectOption{
		{Label: "A", Value: "a"},
		{Label: "B", Value: "b"},
	}, nil)
	m.selectIndex = 0

	m.handleSelectKey(tea.KeyMsg{Type: tea.KeyUp})

	if m.selectIndex != 0 {
		t.Errorf("expected selectIndex=0 at top boundary, got %d", m.selectIndex)
	}
}

func TestHandleSelectKey_DownAtBottom(t *testing.T) {
	m := NewWithTargets(nil)
	m.showSelect("Test:", []SelectOption{
		{Label: "A", Value: "a"},
		{Label: "B", Value: "b"},
	}, nil)
	m.selectIndex = 1

	m.handleSelectKey(tea.KeyMsg{Type: tea.KeyDown})

	if m.selectIndex != 1 {
		t.Errorf("expected selectIndex=1 at bottom boundary, got %d", m.selectIndex)
	}
}

// ===========================================================================
// ConfirmQuit — uppercase N
// ===========================================================================

func TestConfirmQuit_UpperN_Cancels(t *testing.T) {
	m := NewWithTargets(nil)
	m.handleResize(120, 40)
	m.ready = true
	m.inputMode = InputConfirmQuit

	result, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'N'}})
	rm := result.(Model)

	if cmd != nil {
		t.Error("expected nil cmd on uppercase N")
	}
	if rm.inputMode != InputNormal {
		t.Errorf("expected InputNormal after uppercase N, got %d", rm.inputMode)
	}
}

// ===========================================================================
// Update() — WindowSizeMsg with very tiny values
// ===========================================================================

func TestUpdate_WindowSizeMsg_TinyDimensions(t *testing.T) {
	m := NewWithTargets(nil)

	result, _ := m.Update(tea.WindowSizeMsg{Width: 1, Height: 1})
	rm := result.(Model)

	if !rm.ready {
		t.Error("expected ready=true even with tiny dimensions")
	}
}

// ===========================================================================
// handleAgentEvent — EventSubTaskComplete matching by TaskID
// ===========================================================================

func TestHandleAgentEvent_SubTaskComplete_MatchesTaskID(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true

	// Add two subtask blocks
	_ = m.handleAgentEvent(agent.Event{
		TargetID: 1,
		Type:     agent.EventSubTaskStart,
		TaskID:   "task-A",
		Message:  "Task A",
	})
	_ = m.handleAgentEvent(agent.Event{
		TargetID: 1,
		Type:     agent.EventSubTaskStart,
		TaskID:   "task-B",
		Message:  "Task B",
	})

	// Complete task-A (first one) — should match by TaskID
	_ = m.handleAgentEvent(agent.Event{
		TargetID: 1,
		Type:     agent.EventSubTaskComplete,
		TaskID:   "task-A",
	})

	// Find the task-A block and verify it's done
	foundA := false
	foundBNotDone := false
	for _, b := range t1.Blocks {
		if b.Type == agent.BlockSubTask && b.TaskID == "task-A" && b.TaskDone {
			foundA = true
		}
		if b.Type == agent.BlockSubTask && b.TaskID == "task-B" && !b.TaskDone {
			foundBNotDone = true
		}
	}
	if !foundA {
		t.Error("expected task-A to be marked done")
	}
	if !foundBNotDone {
		t.Error("expected task-B to still be pending")
	}
}

// ===========================================================================
// handleAgentEvent — EventAddTarget with team (success case)
// ===========================================================================

func TestHandleAgentEvent_EventAddTarget_WithTeam(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	cfg := agent.TeamConfig{
		Events: make(chan agent.Event, 10),
		Brain:  nil,
		Runner: nil,
	}
	team := agent.NewTeam(cfg)

	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true
	m.team = team

	_ = m.handleAgentEvent(agent.Event{
		TargetID: 1,
		Type:     agent.EventAddTarget,
		NewHost:  "10.0.0.2",
	})

	if len(m.targets) != 2 {
		t.Fatalf("expected 2 targets after EventAddTarget, got %d", len(m.targets))
	}
	if m.targets[1].Host != "10.0.0.2" {
		t.Errorf("expected new target host '10.0.0.2', got %q", m.targets[1].Host)
	}
}

// ===========================================================================
// View() — basic rendering tests
// ===========================================================================

func TestView_NotReady_ShowsStartup(t *testing.T) {
	m := NewWithTargets(nil)
	// ready is false by default

	view := m.View()
	if !strings.Contains(view, "Starting Pentecter") {
		t.Error("expected 'Starting Pentecter' when not ready")
	}
}

func TestView_Ready_NoTarget_ShowsHeader(t *testing.T) {
	m := NewWithTargets(nil)
	m.handleResize(120, 40)
	m.ready = true

	view := m.View()
	if !strings.Contains(view, "PENTECTER") {
		t.Error("expected 'PENTECTER' in rendered view")
	}
}

func TestView_SelectMode(t *testing.T) {
	m := NewWithTargets(nil)
	m.handleResize(120, 40)
	m.ready = true
	m.showSelect("Pick one:", []SelectOption{
		{Label: "Alpha", Value: "a"},
		{Label: "Beta", Value: "b"},
	}, nil)

	view := m.View()
	if !strings.Contains(view, "Alpha") {
		t.Error("expected 'Alpha' in select mode view")
	}
}
