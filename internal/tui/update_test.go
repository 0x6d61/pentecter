package tui

import (
	"strings"
	"testing"
	"time"

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
