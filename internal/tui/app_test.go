package tui

import (
	"bytes"
	"strings"
	"testing"

	"github.com/0x6d61/pentecter/internal/agent"
)

func TestNewApp_EmptyTargets(t *testing.T) {
	a := NewApp(nil)
	if a == nil {
		t.Fatal("expected non-nil App")
	}
	if len(a.targets) != 0 {
		t.Errorf("expected 0 targets, got %d", len(a.targets))
	}
	if a.activeTarget() != nil {
		t.Error("expected nil activeTarget with no targets")
	}
}

func TestNewApp_WithTargets(t *testing.T) {
	targets := []*agent.Target{
		agent.NewTarget(1, "10.0.0.1"),
		agent.NewTarget(2, "10.0.0.2"),
	}
	a := NewApp(targets)

	if len(a.targets) != 2 {
		t.Errorf("expected 2 targets, got %d", len(a.targets))
	}
	if a.activeTarget() == nil {
		t.Fatal("expected non-nil activeTarget")
	}
	if a.activeTarget().Host != "10.0.0.1" {
		t.Errorf("expected first target host '10.0.0.1', got %q", a.activeTarget().Host)
	}
}

func TestTargetByID(t *testing.T) {
	targets := []*agent.Target{
		agent.NewTarget(1, "10.0.0.1"),
		agent.NewTarget(2, "10.0.0.2"),
	}
	a := NewApp(targets)

	if a.targetByID(1).Host != "10.0.0.1" {
		t.Error("expected target 1 to be 10.0.0.1")
	}
	if a.targetByID(2).Host != "10.0.0.2" {
		t.Error("expected target 2 to be 10.0.0.2")
	}
	if a.targetByID(99) != nil {
		t.Error("expected nil for unknown target ID")
	}
}

func TestBuildPrompt_NoTarget(t *testing.T) {
	a := NewApp(nil)
	a.width = 40
	prompt := a.buildPrompt()
	if !strings.Contains(prompt, ">") {
		t.Error("prompt should contain > character")
	}
	// Simple prompt — no dividers
	if strings.Contains(prompt, "─") {
		t.Error("prompt should not contain dividers")
	}
}

func TestBuildPrompt_WithTarget(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.5")
	a := NewApp([]*agent.Target{target})
	a.width = 60
	prompt := a.buildPrompt()
	if !strings.Contains(prompt, ">") {
		t.Error("prompt should contain > character")
	}
}

func TestBuildPrompt_ProposalMode(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.5")
	a := NewApp([]*agent.Target{target})
	a.width = 60
	a.inputMode = ModeProposal
	prompt := a.buildPrompt()
	if !strings.Contains(prompt, "approve?") {
		t.Error("proposal mode prompt should contain 'approve?'")
	}
	if !strings.Contains(prompt, "[y/n/e]") {
		t.Error("proposal mode prompt should contain '[y/n/e]'")
	}
}

func TestBuildPrompt_SelectMode(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.5")
	a := NewApp([]*agent.Target{target})
	a.width = 60
	a.inputMode = ModeSelect
	a.selectOpts = []SelectOption{
		{Label: "Option 1", Value: "1"},
		{Label: "Option 2", Value: "2"},
	}
	prompt := a.buildPrompt()
	if !strings.Contains(prompt, "select") {
		t.Error("select mode prompt should contain 'select'")
	}
	if !strings.Contains(prompt, "[1-2/q]") {
		t.Error("select mode prompt should contain option range")
	}
}

func TestBuildPrompt_ConfirmQuitMode(t *testing.T) {
	a := NewApp(nil)
	a.width = 40
	a.inputMode = ModeConfirmQuit
	prompt := a.buildPrompt()
	if !strings.Contains(prompt, "Quit") {
		t.Error("quit mode prompt should contain 'Quit'")
	}
	if !strings.Contains(prompt, "[y/n]") {
		t.Error("quit mode prompt should contain '[y/n]'")
	}
}

func TestBuildStatusText_NoTarget(t *testing.T) {
	a := NewApp(nil)
	status := a.buildStatusText()
	if status != "" {
		t.Errorf("expected empty status with no target, got %q", status)
	}
}

func TestBuildStatusText_WithTarget(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.5")
	a := NewApp([]*agent.Target{target})
	a.CurrentProvider = "anthropic"
	a.CurrentModel = "claude-sonnet-4-6"
	status := a.buildStatusText()
	if !strings.Contains(status, "10.0.0.5") {
		t.Error("status should contain target host")
	}
	if !strings.Contains(status, "anthropic/claude-sonnet-4-6") {
		t.Error("status should contain model info")
	}
}

func TestLogSystem_WithTarget(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	a := newTestApp([]*agent.Target{target})

	a.logSystem("test message")

	if len(target.Blocks) != 1 {
		t.Fatalf("expected 1 block, got %d", len(target.Blocks))
	}
	if target.Blocks[0].SystemMsg != "test message" {
		t.Errorf("expected 'test message', got %q", target.Blocks[0].SystemMsg)
	}
}

func TestLogSystem_NoTarget(t *testing.T) {
	a := newTestApp(nil)

	a.logSystem("global message")

	if len(a.globalLogs) != 1 {
		t.Fatalf("expected 1 global log, got %d", len(a.globalLogs))
	}
	if a.globalLogs[0] != "global message" {
		t.Errorf("expected 'global message', got %q", a.globalLogs[0])
	}
}

func TestPrintWelcome_NoTargets(t *testing.T) {
	var buf bytes.Buffer
	a := NewApp(nil)
	a.testWriter = &buf

	a.printWelcome()

	output := buf.String()
	if output == "" {
		t.Error("expected non-empty welcome output")
	}
}

func TestPrintWelcome_WithTargets(t *testing.T) {
	var buf bytes.Buffer
	targets := []*agent.Target{agent.NewTarget(1, "10.0.0.5")}
	a := NewApp(targets)
	a.testWriter = &buf

	a.printWelcome()

	output := buf.String()
	if output == "" {
		t.Error("expected non-empty welcome output")
	}
}

func TestWriter_TestWriter(t *testing.T) {
	var buf bytes.Buffer
	a := NewApp(nil)
	a.testWriter = &buf

	w := a.writer()
	if w != &buf {
		t.Error("expected testWriter to be returned")
	}
}

func TestWriter_Fallback(t *testing.T) {
	a := NewApp(nil)
	w := a.writer()
	if w == nil {
		t.Error("expected non-nil writer fallback")
	}
}

func TestSetupLayout_TestMode(t *testing.T) {
	a := newTestApp(nil)
	a.setupLayout()

	// In test mode, setupLayout sets default dimensions
	if a.width != 80 {
		t.Errorf("expected width 80, got %d", a.width)
	}
	if a.height != 24 {
		t.Errorf("expected height 24, got %d", a.height)
	}
}

func TestBuildPrompt_TwoLine(t *testing.T) {
	a := NewApp(nil)
	a.width = 50
	prompt := a.buildPrompt()

	// Prompt should be two-line: \n + "> "
	lines := strings.Split(prompt, "\n")
	if len(lines) != 2 {
		t.Errorf("prompt should be two-line (blank + prompt), got %d lines", len(lines))
	}
	// First line is empty (blank separator)
	if lines[0] != "" {
		t.Errorf("first line should be empty, got %q", lines[0])
	}
	// Second line contains >
	if !strings.Contains(lines[1], ">") {
		t.Error("second line should contain > character")
	}
}

func TestPromptEchoLines_ShortText(t *testing.T) {
	a := NewApp(nil)
	a.width = 80
	// blank(1) + "> a"(1) = 2
	n := a.promptEchoLines("a")
	if n != 2 {
		t.Errorf("expected 2 lines for short text, got %d", n)
	}
}

func TestPromptEchoLines_EmptyText(t *testing.T) {
	a := NewApp(nil)
	a.width = 80
	// blank(1) + "> "(1) = 2
	n := a.promptEchoLines("")
	if n != 2 {
		t.Errorf("expected 2 lines for empty text, got %d", n)
	}
}

func TestPromptEchoLines_WrappingText(t *testing.T) {
	a := NewApp(nil)
	a.width = 20
	// blank(1) + "> " + 30 chars = 32 → ceil(32/20) = 2 input lines
	// 1 + 2 = 3
	longText := strings.Repeat("x", 30)
	n := a.promptEchoLines(longText)
	if n != 3 {
		t.Errorf("expected 3 lines for wrapping text at width=20, got %d", n)
	}
}

func TestPromptEchoLines_ExactWidthNoWrap(t *testing.T) {
	a := NewApp(nil)
	a.width = 80
	// blank(1) + "> " + 78 chars = 80 → 1 input line
	// 1 + 1 = 2
	text := strings.Repeat("a", 78)
	n := a.promptEchoLines(text)
	if n != 2 {
		t.Errorf("expected 2 lines for exact width text, got %d", n)
	}
}

func TestPromptEchoLines_OneCharOverWidth(t *testing.T) {
	a := NewApp(nil)
	a.width = 80
	// blank(1) + "> " + 79 chars = 81 → ceil(81/80) = 2 input lines
	// 1 + 2 = 3
	text := strings.Repeat("a", 79)
	n := a.promptEchoLines(text)
	if n != 3 {
		t.Errorf("expected 3 lines for text 1 char over width, got %d", n)
	}
}

func TestClearPromptEcho_TestMode(t *testing.T) {
	a := newTestApp(nil)
	// Should not panic in test mode (testWriter != nil → no-op)
	a.clearPromptEcho("test")
}

func TestBuildStatusText_Empty(t *testing.T) {
	a := NewApp(nil)
	a.width = 80
	// No target, no model → buildStatusText() == ""
	status := a.buildStatusText()
	if status != "" {
		t.Errorf("expected empty status, got %q", status)
	}
}

func TestBuildPrompt_SpinnerMode(t *testing.T) {
	a := NewApp(nil)
	a.width = 60
	// Normal mode should not have mode hints
	prompt := a.buildPrompt()
	if strings.Contains(prompt, "approve?") || strings.Contains(prompt, "select") {
		t.Error("normal mode should not have mode hints")
	}
}

// --- Multiline input tests ---

func TestResetMultiline(t *testing.T) {
	a := newTestApp(nil)
	a.multilineBuffer = []string{"line1", "line2"}
	a.multilineMode = true
	a.lastLineBuf = "partial"

	a.resetMultiline()

	if a.multilineBuffer != nil {
		t.Errorf("expected nil multilineBuffer, got %v", a.multilineBuffer)
	}
	if a.multilineMode {
		t.Error("expected multilineMode to be false")
	}
	if a.lastLineBuf != "" {
		t.Errorf("expected empty lastLineBuf, got %q", a.lastLineBuf)
	}
}

func TestBuildPrompt_MultilineMode(t *testing.T) {
	a := NewApp(nil)
	a.width = 80
	a.multilineMode = true

	prompt := a.buildPrompt()
	if prompt != "... " {
		t.Errorf("expected '... ' prompt in multiline mode, got %q", prompt)
	}
}

func TestPromptEchoLines_MultilineMode(t *testing.T) {
	a := NewApp(nil)
	a.width = 80
	a.multilineMode = true

	// "... " is a single line, no \n prefix → promptEchoLines should return 1
	n := a.promptEchoLines("hello")
	// "... hello" = 9 chars → fits in 80 cols → 1 line
	if n != 1 {
		t.Errorf("expected 1 line for multiline prompt, got %d", n)
	}
}

func TestMultiline_AccumulateAndJoin(t *testing.T) {
	a := newTestApp(nil)

	// Simulate Ctrl+N twice to accumulate 2 lines, then Enter to join
	a.multilineBuffer = append(a.multilineBuffer, "first line")
	a.multilineMode = true
	a.multilineBuffer = append(a.multilineBuffer, "second line")

	// Simulate Enter: append current line and join
	currentLine := "third line"
	a.multilineBuffer = append(a.multilineBuffer, currentLine)
	fullText := strings.Join(a.multilineBuffer, "\n")
	a.resetMultiline()

	expected := "first line\nsecond line\nthird line"
	if fullText != expected {
		t.Errorf("expected %q, got %q", expected, fullText)
	}

	// Verify reset
	if a.multilineMode {
		t.Error("expected multilineMode false after reset")
	}
	if a.multilineBuffer != nil {
		t.Errorf("expected nil multilineBuffer after reset, got %v", a.multilineBuffer)
	}
}

func TestMultiline_BackspacePop(t *testing.T) {
	a := newTestApp(nil)
	a.multilineBuffer = []string{"line1", "line2"}
	a.multilineMode = true

	// Simulate backspace on empty buffer: pop last line
	popped := a.multilineBuffer[len(a.multilineBuffer)-1]
	a.multilineBuffer = a.multilineBuffer[:len(a.multilineBuffer)-1]

	if popped != "line2" {
		t.Errorf("expected popped 'line2', got %q", popped)
	}
	if len(a.multilineBuffer) != 1 {
		t.Errorf("expected 1 remaining line, got %d", len(a.multilineBuffer))
	}
	if a.multilineBuffer[0] != "line1" {
		t.Errorf("expected remaining line 'line1', got %q", a.multilineBuffer[0])
	}
	// Still in multiline mode (buffer not empty)
	if !a.multilineMode {
		t.Error("expected multilineMode to remain true with non-empty buffer")
	}
}

func TestMultiline_BackspaceExitsMode(t *testing.T) {
	a := newTestApp(nil)
	a.multilineBuffer = []string{"only line"}
	a.multilineMode = true

	// Pop the last line
	popped := a.multilineBuffer[len(a.multilineBuffer)-1]
	a.multilineBuffer = a.multilineBuffer[:len(a.multilineBuffer)-1]
	if len(a.multilineBuffer) == 0 {
		a.multilineMode = false
	}

	if popped != "only line" {
		t.Errorf("expected popped 'only line', got %q", popped)
	}
	if a.multilineMode {
		t.Error("expected multilineMode to be false after popping last line")
	}
	if len(a.multilineBuffer) != 0 {
		t.Errorf("expected empty buffer, got %d items", len(a.multilineBuffer))
	}
}

func TestPrintReconTree_BoxOutput(t *testing.T) {
	var buf bytes.Buffer
	a := NewApp(nil)
	a.testWriter = &buf
	a.width = 60

	treeOutput := "10.0.0.5\n├── :22 (ssh) [Done]\n└── :80 (http) [InProgress]"
	a.printReconTree("10.0.0.5", treeOutput)

	output := buf.String()
	// Should contain the title
	if !strings.Contains(output, "RECON TREE") {
		t.Error("expected output to contain 'RECON TREE'")
	}
	if !strings.Contains(output, "10.0.0.5") {
		t.Error("expected output to contain host '10.0.0.5'")
	}
	// Should contain the tree content
	if !strings.Contains(output, ":22") {
		t.Error("expected output to contain port ':22'")
	}
	if !strings.Contains(output, ":80") {
		t.Error("expected output to contain port ':80'")
	}
	// Should contain rounded border characters
	if !strings.Contains(output, "╭") || !strings.Contains(output, "╰") {
		t.Error("expected output to contain rounded border characters")
	}
}

func TestPrintReconTree_NarrowWidth(t *testing.T) {
	var buf bytes.Buffer
	a := NewApp(nil)
	a.testWriter = &buf
	a.width = 30

	a.printReconTree("host", "tree")

	output := buf.String()
	// Should still produce bordered output
	if !strings.Contains(output, "╭") || !strings.Contains(output, "╰") {
		t.Error("expected bordered output even at narrow width")
	}
}

func TestMultiline_EmptyLine(t *testing.T) {
	a := newTestApp(nil)

	// Accumulate lines including an empty one
	a.multilineBuffer = append(a.multilineBuffer, "first")
	a.multilineBuffer = append(a.multilineBuffer, "")
	a.multilineBuffer = append(a.multilineBuffer, "third")
	a.multilineMode = true

	// Join with current line
	a.multilineBuffer = append(a.multilineBuffer, "fourth")
	fullText := strings.Join(a.multilineBuffer, "\n")

	expected := "first\n\nthird\nfourth"
	if fullText != expected {
		t.Errorf("expected %q, got %q", expected, fullText)
	}
}
