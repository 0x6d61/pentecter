package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/0x6d61/pentecter/internal/agent"
)

// ---------------------------------------------------------------------------
// View
// ---------------------------------------------------------------------------

func TestView_NotReady(t *testing.T) {
	m := NewWithTargets(nil)
	// ready is false by default

	output := m.View()

	if !strings.Contains(output, "Starting Pentecter") {
		t.Errorf("expected loading message when not ready, got %q", output)
	}
}

func TestView_ReadyWithTargets(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	t1.AddLog(agent.SourceSystem, "Session started")
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true
	m.rebuildViewport()

	output := m.View()

	if output == "" {
		t.Fatal("expected non-empty view output when ready")
	}
	if strings.Contains(output, "Starting Pentecter") {
		t.Error("should not show loading message when ready")
	}
	// Should contain the app name
	if !strings.Contains(output, "PENTECTER") {
		t.Error("expected PENTECTER in the view output")
	}
}

func TestView_ReadyNoTargets(t *testing.T) {
	m := NewWithTargets(nil)
	m.handleResize(120, 40)
	m.ready = true
	m.rebuildViewport()

	output := m.View()

	if output == "" {
		t.Fatal("expected non-empty view output")
	}
	if !strings.Contains(output, "PENTECTER") {
		t.Error("expected PENTECTER in the view output")
	}
}

// ---------------------------------------------------------------------------
// renderStatusBar
// ---------------------------------------------------------------------------

func TestRenderStatusBar_WithTarget(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	t1.Status = agent.StatusScanning
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true

	output := m.renderStatusBar()

	if !strings.Contains(output, "PENTECTER") {
		t.Error("expected PENTECTER in status bar")
	}
	if !strings.Contains(output, "10.0.0.1") {
		t.Error("expected target host in status bar")
	}
}

func TestRenderStatusBar_NoTarget(t *testing.T) {
	m := NewWithTargets(nil)
	m.handleResize(120, 40)
	m.ready = true

	output := m.renderStatusBar()

	if !strings.Contains(output, "PENTECTER") {
		t.Error("expected PENTECTER in status bar")
	}
	if !strings.Contains(output, "No target selected") {
		t.Error("expected 'No target selected' in status bar")
	}
}

// ---------------------------------------------------------------------------
// renderFocusIndicator
// ---------------------------------------------------------------------------

func TestRenderFocusIndicator_List(t *testing.T) {
	m := NewWithTargets(nil)
	m.focus = FocusList

	output := m.renderFocusIndicator()

	if !strings.Contains(output, "[LIST]") {
		t.Error("expected [LIST] in focus indicator")
	}
	if !strings.Contains(output, "[LOG]") {
		t.Error("expected [LOG] in focus indicator")
	}
	if !strings.Contains(output, "[INPUT]") {
		t.Error("expected [INPUT] in focus indicator")
	}
}

func TestRenderFocusIndicator_Viewport(t *testing.T) {
	m := NewWithTargets(nil)
	m.focus = FocusViewport

	output := m.renderFocusIndicator()

	if !strings.Contains(output, "[LIST]") {
		t.Error("expected [LIST] in focus indicator")
	}
	if !strings.Contains(output, "[LOG]") {
		t.Error("expected [LOG] in focus indicator")
	}
	if !strings.Contains(output, "[INPUT]") {
		t.Error("expected [INPUT] in focus indicator")
	}
}

func TestRenderFocusIndicator_Input(t *testing.T) {
	m := NewWithTargets(nil)
	m.focus = FocusInput

	output := m.renderFocusIndicator()

	if !strings.Contains(output, "[LIST]") {
		t.Error("expected [LIST] in focus indicator")
	}
	if !strings.Contains(output, "[LOG]") {
		t.Error("expected [LOG] in focus indicator")
	}
	if !strings.Contains(output, "[INPUT]") {
		t.Error("expected [INPUT] in focus indicator")
	}
}

// ---------------------------------------------------------------------------
// renderInputBar
// ---------------------------------------------------------------------------

func TestRenderInputBar_FocusList(t *testing.T) {
	m := NewWithTargets(nil)
	m.handleResize(120, 40)
	m.ready = true
	m.focus = FocusList

	output := m.renderInputBar()

	if !strings.Contains(output, "Select target") {
		t.Errorf("expected '[List]' hint in input bar, got %q", output)
	}
}

func TestRenderInputBar_FocusViewport(t *testing.T) {
	m := NewWithTargets(nil)
	m.handleResize(120, 40)
	m.ready = true
	m.focus = FocusViewport

	output := m.renderInputBar()

	if !strings.Contains(output, "Scroll") {
		t.Errorf("expected '[Log]' hint in input bar, got %q", output)
	}
}

func TestRenderInputBar_FocusInput(t *testing.T) {
	m := NewWithTargets(nil)
	m.handleResize(120, 40)
	m.ready = true
	m.focus = FocusInput

	output := m.renderInputBar()

	if !strings.Contains(output, ">") {
		t.Errorf("expected '>' prompt in input bar, got %q", output)
	}
}

func TestRenderInputBar_SelectMode(t *testing.T) {
	m := NewWithTargets(nil)
	m.handleResize(120, 40)
	m.ready = true

	m.showSelect("Choose:", []SelectOption{
		{Label: "A", Value: "a"},
		{Label: "B", Value: "b"},
	}, nil)

	output := m.renderInputBar()

	if !strings.Contains(output, "Choose:") {
		t.Error("expected select title in input bar during select mode")
	}
	if !strings.Contains(output, "A") {
		t.Error("expected option A in input bar during select mode")
	}
}

// ---------------------------------------------------------------------------
// rebuildViewport — TurnSeparator / CommandResult
// ---------------------------------------------------------------------------

func TestRebuildViewport_TurnSeparator(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	t1.Logs = append(t1.Logs, agent.LogEntry{
		Time:       time.Now(),
		Source:     agent.SourceSystem,
		Message:    "Turn 3",
		Type:       agent.EventTurnStart,
		TurnNumber: 3,
	})
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true
	m.rebuildViewport()

	content := m.viewport.View()
	if !strings.Contains(content, "Turn 3") {
		t.Errorf("expected 'Turn 3' in viewport, got: %s", content)
	}
}

func TestRebuildViewport_CommandResult_Success(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	t1.Logs = append(t1.Logs, agent.LogEntry{
		Time:     time.Now(),
		Source:   agent.SourceTool,
		Message:  "exit 0 (5 lines)",
		Type:     agent.EventCommandResult,
		ExitCode: 0,
	})
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true
	m.rebuildViewport()

	content := m.viewport.View()
	if !strings.Contains(content, "exit 0") {
		t.Errorf("expected 'exit 0' in viewport, got: %s", content)
	}
}

func TestRebuildViewport_CommandResult_Failure(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	t1.Logs = append(t1.Logs, agent.LogEntry{
		Time:     time.Now(),
		Source:   agent.SourceTool,
		Message:  "exit 2: SyntaxError: invalid syntax",
		Type:     agent.EventCommandResult,
		ExitCode: 2,
	})
	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(120, 40)
	m.ready = true
	m.rebuildViewport()

	content := m.viewport.View()
	if !strings.Contains(content, "exit 2") {
		t.Errorf("expected 'exit 2' in viewport, got: %s", content)
	}
}

// ---------------------------------------------------------------------------
// softWrap
// ---------------------------------------------------------------------------

func TestSoftWrap_ShortText(t *testing.T) {
	result := softWrap("hello world", 40)
	if result != "hello world" {
		t.Errorf("short text should not wrap, got %q", result)
	}
}

func TestSoftWrap_LongText(t *testing.T) {
	result := softWrap("aaa bbb ccc ddd eee", 11)
	lines := strings.Split(result, "\n")
	if len(lines) < 2 {
		t.Errorf("expected wrapping, got single line: %q", result)
	}
	for _, line := range lines {
		if len(line) > 11 {
			t.Errorf("line exceeds maxWidth: %q (len=%d)", line, len(line))
		}
	}
}

func TestSoftWrap_ZeroWidth(t *testing.T) {
	result := softWrap("hello", 0)
	if result != "hello" {
		t.Errorf("zero width should return original, got %q", result)
	}
}

func TestSoftWrap_SingleLongWord(t *testing.T) {
	result := softWrap("abcdefghijklmnop", 5)
	// Single long word with no spaces — force-break at width
	lines := strings.Split(result, "\n")
	for _, line := range lines {
		if len(line) > 5 {
			t.Errorf("line exceeds maxWidth after force-break: %q (len=%d)", line, len(line))
		}
	}
}

func TestSoftWrap_EmptyString(t *testing.T) {
	result := softWrap("", 40)
	if result != "" {
		t.Errorf("empty string should return empty, got %q", result)
	}
}

// ---------------------------------------------------------------------------
// rebuildViewport — Long line wrapping
// ---------------------------------------------------------------------------

func TestRebuildViewport_LongLineWraps(t *testing.T) {
	t1 := agent.NewTarget(1, "10.0.0.1")
	// Create a message that's longer than a narrow viewport
	longMsg := strings.Repeat("word ", 30) // ~150 chars
	t1.AddLog(agent.SourceTool, longMsg)

	m := NewWithTargets([]*agent.Target{t1})
	m.handleResize(60, 40) // narrow viewport
	m.ready = true
	m.rebuildViewport()

	content := m.viewport.View()
	lines := strings.Split(content, "\n")

	// The long message should be split across multiple lines
	// (the original was ~150 chars, viewport is ~24 chars for content after prefix)
	foundWordLine := false
	for _, line := range lines {
		if strings.Contains(line, "word") {
			foundWordLine = true
		}
	}
	if !foundWordLine {
		t.Error("expected 'word' to appear in wrapped viewport content")
	}

	// Count lines with "word" — should be more than 1 due to wrapping
	wordLineCount := 0
	for _, line := range lines {
		if strings.Contains(line, "word") {
			wordLineCount++
		}
	}
	if wordLineCount < 2 {
		t.Errorf("expected long message to wrap across multiple lines, got %d lines with 'word'", wordLineCount)
	}
}

// ---------------------------------------------------------------------------
// max
// ---------------------------------------------------------------------------

func TestMax_AGreaterThanB(t *testing.T) {
	result := max(10, 5)
	if result != 10 {
		t.Errorf("expected 10, got %d", result)
	}
}

func TestMax_BGreaterThanA(t *testing.T) {
	result := max(3, 8)
	if result != 8 {
		t.Errorf("expected 8, got %d", result)
	}
}

func TestMax_Equal(t *testing.T) {
	result := max(7, 7)
	if result != 7 {
		t.Errorf("expected 7, got %d", result)
	}
}

func TestMax_Negative(t *testing.T) {
	result := max(-5, -2)
	if result != -2 {
		t.Errorf("expected -2, got %d", result)
	}
}

func TestMax_Zero(t *testing.T) {
	result := max(0, 0)
	if result != 0 {
		t.Errorf("expected 0, got %d", result)
	}
}

// ---------------------------------------------------------------------------
// targetListItem — Title, Description, FilterValue
// ---------------------------------------------------------------------------

func TestTargetListItem_Title_AllStatuses(t *testing.T) {
	statuses := []struct {
		status agent.Status
		icon   string
	}{
		{agent.StatusIdle, "○"},
		{agent.StatusScanning, "◎"},
		{agent.StatusRunning, "▶"},
		{agent.StatusPaused, "⏸"},
		{agent.StatusPwned, "⚡"},
		{agent.StatusFailed, "✗"},
	}

	for _, tt := range statuses {
		t.Run(string(tt.status), func(t *testing.T) {
			target := agent.NewTarget(1, "10.0.0.1")
			target.Status = tt.status
			item := targetListItem{t: target}

			title := item.Title()
			if !strings.Contains(title, tt.icon) {
				t.Errorf("expected icon %q in title for status %s, got %q", tt.icon, tt.status, title)
			}
			if !strings.Contains(title, "10.0.0.1") {
				t.Errorf("expected host in title, got %q", title)
			}
		})
	}
}

func TestTargetListItem_Description_NoProposal(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	target.Status = agent.StatusScanning
	item := targetListItem{t: target}

	desc := item.Description()
	if !strings.Contains(desc, "SCANNING") {
		t.Errorf("expected SCANNING in description, got %q", desc)
	}
	if strings.Contains(desc, "APPROVAL") {
		t.Error("should not contain APPROVAL without a proposal")
	}
}

func TestTargetListItem_Description_WithProposal(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	target.SetProposal(&agent.Proposal{
		Description: "Run nmap",
		Tool:        "nmap",
		Args:        []string{"-sV"},
	})
	item := targetListItem{t: target}

	desc := item.Description()
	if !strings.Contains(desc, "APPROVAL") {
		t.Errorf("expected APPROVAL in description when proposal is set, got %q", desc)
	}
}

func TestTargetListItem_FilterValue(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.5")
	item := targetListItem{t: target}

	fv := item.FilterValue()
	if fv != "10.0.0.5" {
		t.Errorf("expected filter value '10.0.0.5', got %q", fv)
	}
}

func TestTargetListItem_Title_UnknownStatus(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	target.Status = agent.Status("UNKNOWN")
	item := targetListItem{t: target}

	title := item.Title()
	// Unknown status should use the default (idle) style
	if !strings.Contains(title, "10.0.0.1") {
		t.Errorf("expected host in title for unknown status, got %q", title)
	}
}

func TestTargetListItem_Description_AllStatuses(t *testing.T) {
	statuses := []agent.Status{
		agent.StatusIdle,
		agent.StatusScanning,
		agent.StatusRunning,
		agent.StatusPaused,
		agent.StatusPwned,
		agent.StatusFailed,
	}

	for _, status := range statuses {
		t.Run(string(status), func(t *testing.T) {
			target := agent.NewTarget(1, "10.0.0.1")
			target.Status = status
			item := targetListItem{t: target}

			desc := item.Description()
			if !strings.Contains(desc, string(status)) {
				t.Errorf("expected status %q in description, got %q", status, desc)
			}
		})
	}
}
