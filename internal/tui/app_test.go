package tui

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/gdamore/tcell/v2"

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
	// Simple prompt - no dividers
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

func TestBuildStatusText_WithScroll(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.5")
	a := NewApp([]*agent.Target{target})
	a.outputScroll = 12

	status := a.buildStatusText()
	if !strings.Contains(status, "scroll:12") {
		t.Fatalf("status should contain scroll indicator, got %q", status)
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
	if !strings.Contains(output, "Commands: /targets, /model, /approve, /attackdata, /copy, /skip-recon, /fold, /status") {
		t.Error("welcome output should include command list")
	}
	if !strings.Contains(output, "Input: ip/domain or /target HOST") {
		t.Error("welcome output should include input usage")
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
	if !strings.Contains(output, "Commands: /targets, /model, /approve, /attackdata, /copy, /skip-recon, /fold, /status") {
		t.Error("welcome output should include command list")
	}
	if !strings.Contains(output, "Input: ip/domain or /target HOST") {
		t.Error("welcome output should include input usage")
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
	// blank(1) + "> " + 30 chars = 32 -> ceil(32/20) = 2 input lines
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
	// blank(1) + "> " + 78 chars = 80 -> 1 input line
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
	// blank(1) + "> " + 79 chars = 81 -> ceil(81/80) = 2 input lines
	// 1 + 2 = 3
	text := strings.Repeat("a", 79)
	n := a.promptEchoLines(text)
	if n != 3 {
		t.Errorf("expected 3 lines for text 1 char over width, got %d", n)
	}
}

func TestClearPromptEcho_TestMode(t *testing.T) {
	a := newTestApp(nil)
	// Should not panic in test mode (testWriter != nil -> no-op)
	a.clearPromptEcho("test")
}

func TestBuildStatusText_Empty(t *testing.T) {
	a := NewApp(nil)
	a.width = 80
	// No target, no model -> buildStatusText() == ""
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
	if prompt != "" {
		t.Errorf("expected empty prompt in multiline mode, got %q", prompt)
	}
}

func TestBuildPrompt_MultilineModeNoEllipsis(t *testing.T) {
	a := NewApp(nil)
	a.width = 80
	a.multilineMode = true

	prompt := a.buildPrompt()
	if prompt != "" {
		t.Errorf("expected empty prompt in multiline mode, got %q", prompt)
	}
	if strings.Contains(prompt, "...") {
		t.Error("multiline prompt should not contain '...'")
	}
}

func TestPromptEchoLines_MultilineMode(t *testing.T) {
	a := NewApp(nil)
	a.width = 80
	a.multilineMode = true

	// Empty prompt + text -> promptEchoLines should return 1
	n := a.promptEchoLines("hello")
	// "hello" = 5 chars -> fits in 80 cols -> 1 line
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

func TestPrintAttackData_BoxOutput(t *testing.T) {
	var buf bytes.Buffer
	a := NewApp(nil)
	a.testWriter = &buf
	a.width = 60

	treeOutput := "10.0.0.5\n+-- :22 (ssh) [Done]\n+-- :80 (http) [InProgress]"
	a.printAttackData("10.0.0.5", treeOutput)

	output := buf.String()
	if !strings.Contains(output, "ATTACK DATA") {
		t.Error("expected output to contain 'ATTACK DATA'")
	}
	if !strings.Contains(output, "10.0.0.5") {
		t.Error("expected output to contain host '10.0.0.5'")
	}
	if !strings.Contains(output, ":22") {
		t.Error("expected output to contain port ':22'")
	}
	if !strings.Contains(output, ":80") {
		t.Error("expected output to contain port ':80'")
	}
	if !strings.Contains(output, "+") || !strings.Contains(output, "|") {
		t.Error("expected output to contain ASCII box border characters")
	}
}

func TestPrintAttackData_NarrowWidth(t *testing.T) {
	var buf bytes.Buffer
	a := NewApp(nil)
	a.testWriter = &buf
	a.width = 30

	a.printAttackData("host", "this-is-a-very-long-line-that-must-be-clipped")

	output := strings.TrimSuffix(buf.String(), "\n")
	if !strings.Contains(output, "+") || !strings.Contains(output, "|") {
		t.Error("expected bordered output even at narrow width")
	}
	for i, line := range strings.Split(output, "\n") {
		if w := displayWidth(line); w > a.width {
			t.Fatalf("line %d width exceeds app width: got %d > %d (%q)", i, w, a.width, line)
		}
	}
}

func TestPrintAttackData_FullWidthKeepsBoxAligned(t *testing.T) {
	var buf bytes.Buffer
	a := NewApp(nil)
	a.testWriter = &buf
	a.width = 80

	treeOutput := "/\n+-- finding: \u7ba1\u7406\u8005\u30d1\u30cd\u30eb \u8a8d\u8a3c\u56de\u907f"
	a.printAttackData("10.0.0.5", treeOutput)

	output := strings.TrimSuffix(buf.String(), "\n")
	lines := strings.Split(output, "\n")
	if len(lines) < 3 {
		t.Fatalf("expected at least 3 lines, got %d", len(lines))
	}
	wantW := displayWidth(lines[0])
	for i, line := range lines {
		if gotW := displayWidth(line); gotW != wantW {
			t.Fatalf("line %d width mismatch: got %d, want %d (%q)", i, gotW, wantW, line)
		}
	}
}

func TestPrintAttackData_SanitizesAndTruncatesRows(t *testing.T) {
	var buf bytes.Buffer
	a := NewApp(nil)
	a.testWriter = &buf
	a.width = 28

	treeOutput := "finding: <html><body>very long long long payload</body></html>\nrow\twith\rcontrols\x07bell"
	a.printAttackData("host", treeOutput)

	output := strings.TrimSuffix(buf.String(), "\n")
	if strings.Contains(output, "\t") || strings.Contains(output, "\r") || strings.Contains(output, "\x07") {
		t.Fatal("expected control/tab characters to be sanitized in attack data output")
	}
	if !strings.Contains(output, "...") {
		t.Fatal("expected long row to be truncated with ellipsis")
	}
	for i, line := range strings.Split(output, "\n") {
		if w := displayWidth(line); w > a.width {
			t.Fatalf("line %d width exceeds app width: got %d > %d (%q)", i, w, a.width, line)
		}
	}
}

func TestHandleKeyEvent_CtrlY_EntersCopyMode(t *testing.T) {
	a := NewApp(nil)
	a.width = 80
	a.height = 24
	a.globalLogs = []string{"alpha", "beta", "gamma"}

	quit := a.handleKeyEvent(tcell.NewEventKey(tcell.KeyCtrlY, 0, tcell.ModNone))
	if quit {
		t.Fatal("Ctrl+Y should not request quit")
	}
	if a.inputMode != ModeCopy {
		t.Fatalf("expected ModeCopy after Ctrl+Y, got %d", a.inputMode)
	}
}

func TestCopyMode_ExitRestoresPreviousMode(t *testing.T) {
	a := NewApp(nil)
	a.width = 80
	a.height = 24
	a.inputMode = ModeProposal
	a.globalLogs = []string{"alpha", "beta"}

	quit := a.handleKeyEvent(tcell.NewEventKey(tcell.KeyCtrlY, 0, tcell.ModNone))
	if quit {
		t.Fatal("Ctrl+Y should not request quit")
	}
	if a.inputMode != ModeCopy {
		t.Fatalf("expected ModeCopy after Ctrl+Y, got %d", a.inputMode)
	}

	quit = a.handleKeyEvent(tcell.NewEventKey(tcell.KeyEscape, 0, tcell.ModNone))
	if quit {
		t.Fatal("Esc in copy mode should not request quit")
	}
	if a.inputMode != ModeProposal {
		t.Fatalf("expected mode to restore to ModeProposal, got %d", a.inputMode)
	}
}

func TestCopyMode_YankSelectionToClipboard(t *testing.T) {
	sim := tcell.NewSimulationScreen("")
	if err := sim.Init(); err != nil {
		t.Fatalf("simulation screen init failed: %v", err)
	}
	defer sim.Fini()

	a := NewApp(nil)
	a.SetScreen(sim)
	a.width = 80
	a.height = 24
	a.globalLogs = []string{"line-a", "line-b", "line-c"}

	a.mu.Lock()
	a.enterCopyModeLocked()
	if a.copyCursor != 2 {
		a.mu.Unlock()
		t.Fatalf("expected copy cursor at latest line index 2, got %d", a.copyCursor)
	}
	a.copyAnchor = a.copyCursor
	a.moveCopyCursorLocked(-1)
	a.yankCopySelectionLocked()
	a.exitCopyModeLocked()
	a.mu.Unlock()

	got := string(sim.GetClipboardData())
	if got != "line-b\nline-c" {
		t.Fatalf("unexpected yanked clipboard content: %q", got)
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

// --- Bug 1: lastLineBuf tests ---

func TestBug1_LastLineBufClearedAfterCtrlN(t *testing.T) {
	a := newTestApp(nil)
	a.lastLineBuf = "aaaa"

	// Simulate what Ctrl+N handler does
	saved := a.lastLineBuf
	a.lastLineBuf = "" // Bug 1 fix
	a.multilineBuffer = append(a.multilineBuffer, saved)
	a.multilineMode = true

	if a.lastLineBuf != "" {
		t.Errorf("expected lastLineBuf to be empty after Ctrl+N, got %q", a.lastLineBuf)
	}
	if a.multilineBuffer[0] != "aaaa" {
		t.Errorf("expected 'aaaa' in multilineBuffer, got %q", a.multilineBuffer[0])
	}
}

func TestBug1_LastLineBufUpdatedAfterPop(t *testing.T) {
	a := newTestApp(nil)
	a.multilineBuffer = []string{"aaaa", "bbbb"}
	a.multilineMode = true
	a.lastLineBuf = "cccc"

	// Simulate backspace pop
	popped := a.multilineBuffer[len(a.multilineBuffer)-1]
	a.multilineBuffer = a.multilineBuffer[:len(a.multilineBuffer)-1]
	a.lastLineBuf = popped // Bug 1 fix

	if a.lastLineBuf != "bbbb" {
		t.Errorf("expected lastLineBuf to be 'bbbb' after pop, got %q", a.lastLineBuf)
	}
}

// --- printCmdOutputLine tests ---

func TestPrintCmdOutputLine_WithinThreshold(t *testing.T) {
	var buf bytes.Buffer
	a := NewApp(nil)
	a.testWriter = &buf
	a.width = 80

	// Print 5 lines (at threshold)
	for i := 1; i <= 5; i++ {
		a.printCmdOutputLine(fmt.Sprintf("line %d", i), i)
	}

	output := buf.String()
	// All lines should be present
	for i := 1; i <= 5; i++ {
		if !strings.Contains(output, fmt.Sprintf("line %d", i)) {
			t.Errorf("expected 'line %d' in output", i)
		}
	}
	// No fold indicator
	if strings.Contains(output, "ctrl+o") {
		t.Error("should not contain fold indicator within threshold")
	}
}

func TestPrintCmdOutputLine_PastThreshold(t *testing.T) {
	var buf bytes.Buffer
	a := NewApp(nil)
	a.testWriter = &buf
	a.width = 80

	// Print first 5 lines normally
	for i := 1; i <= 5; i++ {
		a.printCmdOutputLine(fmt.Sprintf("line %d", i), i)
	}
	buf.Reset()

	// 6th line should produce fold indicator instead of line content
	a.printCmdOutputLine("line 6", 6)

	output := buf.String()
	if !strings.Contains(output, "ctrl+o") {
		t.Error("expected fold indicator at 6th line")
	}
	// remaining = 6 - 3 = 3
	if !strings.Contains(output, "+3") {
		t.Error("expected '+3' in fold indicator")
	}
	// Should NOT show the actual line content
	if strings.Contains(output, "line 6") {
		t.Error("should not show line content past threshold")
	}
}

func TestPrintCmdOutputLine_Expanded(t *testing.T) {
	var buf bytes.Buffer
	a := NewApp(nil)
	a.testWriter = &buf
	a.width = 80
	a.logsExpanded = true

	// Even past threshold, should show content when expanded
	a.printCmdOutputLine("line 10", 10)

	output := buf.String()
	if !strings.Contains(output, "line 10") {
		t.Error("expected line content when expanded")
	}
	if strings.Contains(output, "ctrl+o") {
		t.Error("should not show fold indicator when expanded")
	}
}

func TestPrintCmdOutputLine_FirstLinePrefix(t *testing.T) {
	var buf bytes.Buffer
	a := NewApp(nil)
	a.testWriter = &buf
	a.width = 80

	a.printCmdOutputLine("first output", 1)

	output := buf.String()
	// First line should have ⎿ prefix
	if !strings.Contains(output, "⎿") {
		t.Error("expected ⎿ prefix on first output line")
	}
}
