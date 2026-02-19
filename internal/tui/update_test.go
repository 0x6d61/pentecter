package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/0x6d61/pentecter/internal/agent"
	"github.com/0x6d61/pentecter/internal/brain"
	"github.com/0x6d61/pentecter/internal/tools"
)

// ---------------------------------------------------------------------------
// cycleFocus
// ---------------------------------------------------------------------------

func TestCycleFocus_ListToViewport(t *testing.T) {
	m := NewWithTargets(nil)
	m.focus = FocusList

	m.cycleFocus()

	if m.focus != FocusViewport {
		t.Errorf("expected FocusViewport after cycling from FocusList, got %d", m.focus)
	}
}

func TestCycleFocus_ViewportToInput(t *testing.T) {
	m := NewWithTargets(nil)
	m.focus = FocusViewport

	m.cycleFocus()

	if m.focus != FocusInput {
		t.Errorf("expected FocusInput after cycling from FocusViewport, got %d", m.focus)
	}
}

func TestCycleFocus_InputToList(t *testing.T) {
	m := NewWithTargets(nil)
	m.focus = FocusInput

	m.cycleFocus()

	if m.focus != FocusList {
		t.Errorf("expected FocusList after cycling from FocusInput, got %d", m.focus)
	}
}

func TestCycleFocus_FullCycle(t *testing.T) {
	m := NewWithTargets(nil)
	m.focus = FocusList

	m.cycleFocus() // List -> Viewport
	m.cycleFocus() // Viewport -> Input
	m.cycleFocus() // Input -> List

	if m.focus != FocusList {
		t.Errorf("expected FocusList after full cycle, got %d", m.focus)
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

	logsBefore := len(t1.Logs)
	m.submitInput()

	if len(t1.Logs) != logsBefore {
		t.Error("empty input should not add any log entry")
	}
}

func TestSubmitInput_WhitespaceOnly(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.input.SetValue("   ")

	logsBefore := len(t1.Logs)
	m.submitInput()

	if len(t1.Logs) != logsBefore {
		t.Error("whitespace-only input should not add any log entry")
	}
}

func TestSubmitInput_NormalText(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true
	m.input.SetValue("scan the target")

	logsBefore := len(t1.Logs)
	m.submitInput()

	if len(t1.Logs) != logsBefore+1 {
		t.Fatalf("expected 1 new log, got %d", len(t1.Logs)-logsBefore)
	}
	lastLog := t1.Logs[len(t1.Logs)-1]
	if lastLog.Source != agent.SourceUser {
		t.Errorf("expected SourceUser, got %q", lastLog.Source)
	}
	if lastLog.Message != "scan the target" {
		t.Errorf("expected message 'scan the target', got %q", lastLog.Message)
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

	logsBefore := len(t1.Logs)
	m.handleAgentEvent(agent.Event{
		TargetID: 1,
		Type:     agent.EventLog,
		Source:   agent.SourceAI,
		Message:  "Found open port 80",
	})

	if len(t1.Logs) != logsBefore+1 {
		t.Fatalf("expected 1 new log, got %d", len(t1.Logs)-logsBefore)
	}
	if t1.Logs[len(t1.Logs)-1].Message != "Found open port 80" {
		t.Errorf("unexpected message: %q", t1.Logs[len(t1.Logs)-1].Message)
	}
	if t1.Logs[len(t1.Logs)-1].Source != agent.SourceAI {
		t.Errorf("expected SourceAI, got %q", t1.Logs[len(t1.Logs)-1].Source)
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
	m.handleAgentEvent(agent.Event{
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

	logsBefore := len(t1.Logs)
	m.handleAgentEvent(agent.Event{
		TargetID: 1,
		Type:     agent.EventProposal,
		Proposal: nil,
	})

	// nil proposal should not set anything
	if t1.Proposal != nil {
		t.Error("expected proposal to remain nil")
	}
	// No log should be added for nil proposal
	if len(t1.Logs) != logsBefore {
		t.Errorf("expected no new logs for nil proposal, got %d new", len(t1.Logs)-logsBefore)
	}
}

func TestHandleAgentEvent_EventComplete(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true

	logsBefore := len(t1.Logs)
	m.handleAgentEvent(agent.Event{
		TargetID: 1,
		Type:     agent.EventComplete,
		Message:  "Assessment complete",
	})

	if len(t1.Logs) != logsBefore+1 {
		t.Fatalf("expected 1 new log, got %d", len(t1.Logs)-logsBefore)
	}
	if !strings.HasPrefix(t1.Logs[len(t1.Logs)-1].Message, "✅") {
		t.Errorf("expected complete message to start with checkmark, got %q", t1.Logs[len(t1.Logs)-1].Message)
	}
}

func TestHandleAgentEvent_EventError(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true

	logsBefore := len(t1.Logs)
	m.handleAgentEvent(agent.Event{
		TargetID: 1,
		Type:     agent.EventError,
		Message:  "Connection refused",
	})

	if len(t1.Logs) != logsBefore+1 {
		t.Fatalf("expected 1 new log, got %d", len(t1.Logs)-logsBefore)
	}
	lastMsg := t1.Logs[len(t1.Logs)-1].Message
	if !strings.Contains(lastMsg, "Connection refused") {
		t.Errorf("expected error message to contain 'Connection refused', got %q", lastMsg)
	}
	if !strings.HasPrefix(lastMsg, "❌") {
		t.Errorf("expected error message to start with X mark, got %q", lastMsg)
	}
}

func TestHandleAgentEvent_EventAddTarget_NoTeam(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true
	// team is nil

	targetsBefore := len(m.targets)
	m.handleAgentEvent(agent.Event{
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

	logsBefore := len(t1.Logs)
	m.handleAgentEvent(agent.Event{
		TargetID: 1,
		Type:     agent.EventStalled,
		Message:  "Agent stuck",
	})

	// EventStalled adds 2 log entries
	if len(t1.Logs) != logsBefore+2 {
		t.Fatalf("expected 2 new logs for stalled event, got %d", len(t1.Logs)-logsBefore)
	}
	if !strings.HasPrefix(t1.Logs[logsBefore].Message, "⚠") {
		t.Errorf("expected stalled message to start with warning, got %q", t1.Logs[logsBefore].Message)
	}
	if !strings.Contains(t1.Logs[logsBefore+1].Message, "Type a message") {
		t.Errorf("expected guidance message, got %q", t1.Logs[logsBefore+1].Message)
	}
}

func TestHandleAgentEvent_FallbackToActiveTarget(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true

	logsBefore := len(t1.Logs)
	// Send event for non-existent target ID — should fall back to active target
	m.handleAgentEvent(agent.Event{
		TargetID: 999,
		Type:     agent.EventLog,
		Source:   agent.SourceSystem,
		Message:  "Fallback test",
	})

	if len(t1.Logs) != logsBefore+1 {
		t.Fatalf("expected 1 new log via fallback, got %d", len(t1.Logs)-logsBefore)
	}
	if t1.Logs[len(t1.Logs)-1].Message != "Fallback test" {
		t.Errorf("unexpected message: %q", t1.Logs[len(t1.Logs)-1].Message)
	}
}

func TestHandleAgentEvent_NoTargets_NoOp(t *testing.T) {
	m := NewWithTargets(nil)
	m.handleResize(120, 40)
	m.ready = true

	// Should not panic when no targets exist
	m.handleAgentEvent(agent.Event{
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

	logs1Before := len(t1.Logs)
	logs2Before := len(t2.Logs)

	// Send event for t2 (not the active target)
	m.handleAgentEvent(agent.Event{
		TargetID: 2,
		Type:     agent.EventLog,
		Source:   agent.SourceAI,
		Message:  "Target 2 message",
	})

	// t2 should receive the log
	if len(t2.Logs) != logs2Before+1 {
		t.Errorf("expected 1 new log on t2, got %d", len(t2.Logs)-logs2Before)
	}
	// t1 should NOT receive the log
	if len(t1.Logs) != logs1Before {
		t.Errorf("expected no new logs on t1, got %d", len(t1.Logs)-logs1Before)
	}
}

// ---------------------------------------------------------------------------
// extractIPFromText — invalid IP to cover ParseIP failure branch
// ---------------------------------------------------------------------------

func TestExtractIPFromText_InvalidIP(t *testing.T) {
	// 999.999.999.999 matches the regex pattern but fails net.ParseIP
	_, _, ok := extractIPFromText("scan 999.999.999.999 please")
	if ok {
		t.Error("expected ok=false for invalid IP 999.999.999.999")
	}
}

func TestExtractIPFromText_InvalidIP_300(t *testing.T) {
	_, _, ok := extractIPFromText("300.400.500.600")
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
	m.focus = FocusList

	result, _ := m.Update(tea.KeyMsg{Type: tea.KeyTab})
	rm := result.(Model)

	if rm.focus != FocusViewport {
		t.Errorf("expected FocusViewport after Tab from FocusList, got %d", rm.focus)
	}
}

func TestUpdate_CtrlC_Quit(t *testing.T) {
	m := NewWithTargets(nil)
	m.handleResize(120, 40)
	m.ready = true

	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	if cmd == nil {
		t.Error("expected non-nil quit cmd on Ctrl+C")
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
