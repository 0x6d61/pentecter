package tui

import (
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/0x6d61/pentecter/internal/agent"
)

// stripANSI は ANSI エスケープシーケンスを除去する（テスト用ヘルパー）。
var ansiRegex = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func stripANSI(s string) string {
	return ansiRegex.ReplaceAllString(s, "")
}

// ---------------------------------------------------------------------------
// renderCommandBlock
// ---------------------------------------------------------------------------

func TestRenderCommandBlock_HeaderOnly(t *testing.T) {
	b := agent.NewCommandBlock("nmap -sV 10.0.0.5")
	result := renderCommandBlock(b, 80, false)

	if !strings.Contains(result, "●") {
		t.Error("expected bullet '●' in command header")
	}
	if !strings.Contains(result, "nmap -sV 10.0.0.5") {
		t.Error("expected command text in output")
	}
}

func TestRenderCommandBlock_WithOutput(t *testing.T) {
	b := agent.NewCommandBlock("whoami")
	b.Output = []string{"root"}

	result := renderCommandBlock(b, 80, false)

	if !strings.Contains(result, "●") {
		t.Error("expected bullet '●' in command header")
	}
	if !strings.Contains(result, "whoami") {
		t.Error("expected command text in output")
	}
	if !strings.Contains(result, "⎿") {
		t.Error("expected output prefix '⎿' for first output line")
	}
	if !strings.Contains(result, "root") {
		t.Error("expected output content 'root'")
	}
}

func TestRenderCommandBlock_FoldedWhenManyLines(t *testing.T) {
	b := agent.NewCommandBlock("ls -la")
	b.Output = []string{
		"line1", "line2", "line3", "line4", "line5",
		"line6", "line7", "line8", "line9", "line10",
	}

	result := renderCommandBlock(b, 80, false)

	// Should show first 3 lines (previewLines)
	if !strings.Contains(result, "line1") {
		t.Error("expected 'line1' in folded output")
	}
	if !strings.Contains(result, "line2") {
		t.Error("expected 'line2' in folded output")
	}
	if !strings.Contains(result, "line3") {
		t.Error("expected 'line3' in folded output")
	}
	// Should NOT show lines beyond preview
	if strings.Contains(result, "line4") {
		t.Error("expected 'line4' to be hidden when folded")
	}
	if strings.Contains(result, "line10") {
		t.Error("expected 'line10' to be hidden when folded")
	}
	// Should show fold indicator
	if !strings.Contains(result, "+7 lines (ctrl+o)") {
		t.Errorf("expected fold indicator '+7 lines (ctrl+o)', got:\n%s", result)
	}
}

func TestRenderCommandBlock_ExpandedShowsAll(t *testing.T) {
	b := agent.NewCommandBlock("cat /etc/passwd")
	b.Output = []string{
		"line1", "line2", "line3", "line4", "line5",
		"line6", "line7", "line8", "line9", "line10",
	}

	result := renderCommandBlock(b, 80, true)

	// All lines should be visible
	for i := 1; i <= 10; i++ {
		expected := "line" + string(rune('0'+i))
		if i == 10 {
			expected = "line10"
		}
		if !strings.Contains(result, expected) {
			t.Errorf("expected '%s' in expanded output", expected)
		}
	}
	// No fold indicator
	if strings.Contains(result, "ctrl+o") {
		t.Error("expanded output should NOT contain fold indicator")
	}
}

func TestRenderCommandBlock_ExactThresholdNoFold(t *testing.T) {
	b := agent.NewCommandBlock("cmd")
	b.Output = []string{"l1", "l2", "l3", "l4", "l5"} // exactly 5 lines

	result := renderCommandBlock(b, 80, false)

	// Should show all lines — foldThreshold is 5, only fold when >5
	if !strings.Contains(result, "l5") {
		t.Error("expected 'l5' to be shown when exactly at threshold")
	}
	if strings.Contains(result, "ctrl+o") {
		t.Error("should NOT fold when exactly at threshold")
	}
}

func TestRenderCommandBlock_SixLinesFolds(t *testing.T) {
	b := agent.NewCommandBlock("cmd")
	b.Output = []string{"l1", "l2", "l3", "l4", "l5", "l6"} // 6 lines

	result := renderCommandBlock(b, 80, false)

	if !strings.Contains(result, "l3") {
		t.Error("expected 'l3' in preview")
	}
	if strings.Contains(result, "l4") {
		t.Error("expected 'l4' to be hidden")
	}
	if !strings.Contains(result, "+3 lines (ctrl+o)") {
		t.Errorf("expected '+3 lines (ctrl+o)' indicator, got:\n%s", result)
	}
}

func TestRenderCommandBlock_EmptyOutput(t *testing.T) {
	b := agent.NewCommandBlock("true")
	b.Output = nil

	result := renderCommandBlock(b, 80, false)

	if !strings.Contains(result, "● true") {
		t.Error("expected command header with bullet")
	}
	if strings.Contains(result, "⎿") {
		t.Error("should not contain output prefix when no output")
	}
}

// ---------------------------------------------------------------------------
// renderThinkingBlock
// ---------------------------------------------------------------------------

func TestRenderThinkingBlock_InProgress(t *testing.T) {
	b := agent.NewThinkingBlock()
	b.ThinkingDone = false

	result := renderThinkingBlock(b, "⠋")

	if !strings.Contains(result, "Thinking...") {
		t.Errorf("expected 'Thinking...' for in-progress thinking, got: %q", result)
	}
}

func TestRenderThinkingBlock_InProgress_WithSpinner(t *testing.T) {
	b := agent.NewThinkingBlock()
	b.ThinkingDone = false

	// 各スピナーフレームが出力に反映されることを確認
	for _, frame := range []string{"⠋", "⠙", "⠹", "⠸"} {
		result := renderThinkingBlock(b, frame)
		if !strings.Contains(result, frame) {
			t.Errorf("expected spinner frame %q in output, got: %q", frame, result)
		}
		if !strings.Contains(result, "Thinking...") {
			t.Errorf("expected 'Thinking...' text alongside spinner frame %q, got: %q", frame, result)
		}
	}
}

func TestRenderThinkingBlock_Completed(t *testing.T) {
	b := agent.NewThinkingBlock()
	b.ThinkingDone = true
	b.ThinkDuration = 12 * time.Second

	result := renderThinkingBlock(b, "⠋")

	if !strings.Contains(result, "✻") {
		t.Error("expected '✻' in completed thinking block")
	}
	if !strings.Contains(result, "Completed in 12s") {
		t.Errorf("expected 'Completed in 12s', got: %q", result)
	}
	// 完了ブロックにはスピナーフレームが含まれないこと
	if strings.Contains(result, "⠋") {
		t.Error("completed thinking block should NOT contain spinner frame")
	}
}

func TestRenderThinkingBlock_CompletedMinutes(t *testing.T) {
	b := agent.NewThinkingBlock()
	b.ThinkingDone = true
	b.ThinkDuration = 1*time.Minute + 23*time.Second

	result := renderThinkingBlock(b, "⠋")

	if !strings.Contains(result, "Completed in 1m23s") {
		t.Errorf("expected 'Completed in 1m23s', got: %q", result)
	}
}

func TestRenderThinkingBlock_CompletedSubSecond(t *testing.T) {
	b := agent.NewThinkingBlock()
	b.ThinkingDone = true
	b.ThinkDuration = 500 * time.Millisecond

	result := renderThinkingBlock(b, "⠋")

	if !strings.Contains(result, "<1s") {
		t.Errorf("expected '<1s' for sub-second duration, got: %q", result)
	}
}

// ---------------------------------------------------------------------------
// renderAIMessageBlock
// ---------------------------------------------------------------------------

func TestRenderAIMessageBlock_WithMessage(t *testing.T) {
	b := agent.NewAIMessageBlock("Hello, I found a vulnerability.")

	result := renderAIMessageBlock(b, 80)
	stripped := stripANSI(result)

	if !strings.Contains(stripped, "Hello, I found a vulnerability.") {
		t.Errorf("expected message text in output, got stripped: %q", stripped)
	}
}

func TestRenderAIMessageBlock_Empty(t *testing.T) {
	b := agent.NewAIMessageBlock("")

	result := renderAIMessageBlock(b, 80)

	if result != "" {
		t.Errorf("expected empty string for empty message, got: %q", result)
	}
}

func TestRenderAIMessageBlock_Markdown_Bold(t *testing.T) {
	b := agent.NewAIMessageBlock("This is **bold text** here.")

	result := renderAIMessageBlock(b, 80)
	stripped := stripANSI(result)

	// glamour がレンダリングした結果、生の ** マーカーは消えているはず
	if strings.Contains(stripped, "**bold text**") {
		t.Error("expected glamour to render bold text, but raw '**' markers remain")
	}
	// テキスト内容は含まれている
	if !strings.Contains(stripped, "bold text") {
		t.Error("expected 'bold text' in rendered output")
	}
}

func TestRenderAIMessageBlock_Markdown_CodeBlock(t *testing.T) {
	input := "Here is code:\n```bash\necho hello\n```"
	b := agent.NewAIMessageBlock(input)

	result := renderAIMessageBlock(b, 80)
	stripped := stripANSI(result)

	// コードの内容が含まれている
	if !strings.Contains(stripped, "echo hello") {
		t.Errorf("expected 'echo hello' in rendered code block output, got stripped: %q", stripped)
	}
	// 生のバックティックフェンスは消えているはず
	if strings.Contains(stripped, "```") {
		t.Error("expected glamour to render code block, but raw '```' markers remain")
	}
}

func TestRenderAIMessageBlock_Markdown_List(t *testing.T) {
	input := "Findings:\n- item1\n- item2\n- item3"
	b := agent.NewAIMessageBlock(input)

	result := renderAIMessageBlock(b, 80)
	stripped := stripANSI(result)

	if !strings.Contains(stripped, "item1") {
		t.Errorf("expected 'item1' in rendered list output, got stripped: %q", stripped)
	}
	if !strings.Contains(stripped, "item2") {
		t.Errorf("expected 'item2' in rendered list output, got stripped: %q", stripped)
	}
	if !strings.Contains(stripped, "item3") {
		t.Errorf("expected 'item3' in rendered list output, got stripped: %q", stripped)
	}
}

func TestRenderAIMessageBlock_PlainText(t *testing.T) {
	b := agent.NewAIMessageBlock("Just a simple sentence without any markdown.")

	result := renderAIMessageBlock(b, 80)
	stripped := stripANSI(result)

	if !strings.Contains(stripped, "Just a simple sentence without any markdown.") {
		t.Errorf("expected plain text to be preserved in output, got stripped: %q", stripped)
	}
	if result == "" {
		t.Error("expected non-empty output for plain text message")
	}
}

// ---------------------------------------------------------------------------
// renderMarkdown
// ---------------------------------------------------------------------------

func TestRenderMarkdown_BasicMarkdown(t *testing.T) {
	input := "# Heading\n\nSome **bold** text."

	result, err := renderMarkdown(input, 80)

	if err != nil {
		t.Fatalf("renderMarkdown returned error: %v", err)
	}
	if result == "" {
		t.Error("expected non-empty output from renderMarkdown")
	}
	// テキスト内容が含まれている
	if !strings.Contains(result, "Heading") {
		t.Error("expected 'Heading' in rendered output")
	}
	if !strings.Contains(result, "bold") {
		t.Error("expected 'bold' in rendered output")
	}
}

func TestRenderMarkdown_Width(t *testing.T) {
	// 長い行が width に基づいて折り返されることを確認
	longLine := strings.Repeat("word ", 30) // 150文字程度
	input := longLine

	result, err := renderMarkdown(input, 40)

	if err != nil {
		t.Fatalf("renderMarkdown returned error: %v", err)
	}
	if result == "" {
		t.Error("expected non-empty output from renderMarkdown")
	}
	// 出力が複数行に折り返されているはず
	lines := strings.Split(strings.TrimSpace(result), "\n")
	if len(lines) < 2 {
		t.Errorf("expected word wrap to produce multiple lines at width=40, got %d line(s):\n%s", len(lines), result)
	}
}

// ---------------------------------------------------------------------------
// renderMemoryBlock
// ---------------------------------------------------------------------------

func TestRenderMemoryBlock(t *testing.T) {
	b := agent.NewMemoryBlock("HIGH", "SQL Injection found on /login")

	result := renderMemoryBlock(b)

	if !strings.Contains(result, "HIGH") {
		t.Error("expected severity 'HIGH' in output")
	}
	if !strings.Contains(result, "SQL Injection found on /login") {
		t.Error("expected title in output")
	}
}

// ---------------------------------------------------------------------------
// renderSubTaskBlock
// ---------------------------------------------------------------------------

func TestRenderSubTaskBlock_InProgress(t *testing.T) {
	b := agent.NewSubTaskBlock("task-1", "Scan port 80 for vulnerabilities")

	result := renderSubTaskBlock(b, 80, "⠋")

	if !strings.Contains(result, "Scan port 80 for vulnerabilities") {
		t.Error("expected task goal in output")
	}
	// スピナーフレームが表示されること
	if !strings.Contains(result, "⠋") {
		t.Error("expected spinner frame '⠋' for in-progress subtask")
	}
}

func TestRenderSubTaskBlock_InProgress_WithSpinner(t *testing.T) {
	b := agent.NewSubTaskBlock("task-1", "Enumerate SMB shares")

	// 各スピナーフレームが出力に反映されることを確認
	for _, frame := range []string{"⠋", "⠙", "⠹", "⠸"} {
		result := renderSubTaskBlock(b, 80, frame)
		if !strings.Contains(result, frame) {
			t.Errorf("expected spinner frame %q in output, got: %q", frame, result)
		}
		if !strings.Contains(result, "Enumerate SMB shares") {
			t.Errorf("expected task goal alongside spinner frame %q, got: %q", frame, result)
		}
	}
}

func TestRenderSubTaskBlock_Completed(t *testing.T) {
	b := agent.NewSubTaskBlock("task-1", "Scan port 80")
	b.TaskDone = true
	b.TaskDuration = 5 * time.Second

	result := renderSubTaskBlock(b, 80, "⠋")

	// Goal should be present (with strikethrough)
	if !strings.Contains(result, "Scan port 80") {
		t.Error("expected task goal in completed output")
	}
	// Should have checkmark
	if !strings.Contains(result, "✓") {
		t.Error("expected checkmark '✓' in completed subtask")
	}
	// Should have duration
	if !strings.Contains(result, "5s") {
		t.Errorf("expected '5s' duration, got: %q", result)
	}
	// 完了ブロックにはスピナーフレームが含まれないこと
	if strings.Contains(result, "⠋") {
		t.Error("completed subtask block should NOT contain spinner frame")
	}
}

func TestRenderSubTaskBlock_LongGoal_Wraps(t *testing.T) {
	goal := "Perform comprehensive MySQL enumeration on 172.30.0.20 to discover databases, users, and potential injection points"
	b := agent.NewSubTaskBlock("task-1", goal)

	result := renderSubTaskBlock(b, 40, "⠋")

	// ゴール全文が含まれること（折り返しても）
	if !strings.Contains(result, "Perform comprehensive") {
		t.Error("expected start of goal text")
	}
	if !strings.Contains(result, "injection points") {
		t.Error("expected end of goal text")
	}
	// 複数行に折り返されること
	lines := strings.Split(strings.TrimRight(result, "\n"), "\n")
	if len(lines) < 2 {
		t.Errorf("expected multi-line wrap for long goal at width 40, got %d lines", len(lines))
	}
}

// ---------------------------------------------------------------------------
// renderUserInputBlock
// ---------------------------------------------------------------------------

func TestRenderUserInputBlock(t *testing.T) {
	b := agent.NewUserInputBlock("scan all ports")

	result := renderUserInputBlock(b, 80)

	if !strings.Contains(result, ">") {
		t.Error("expected '>' prefix in user input block")
	}
	if !strings.Contains(result, "scan all ports") {
		t.Error("expected user text in output")
	}
}

// ---------------------------------------------------------------------------
// renderSystemBlock
// ---------------------------------------------------------------------------

func TestRenderSystemBlock(t *testing.T) {
	b := agent.NewSystemBlock("Session started")

	result := renderSystemBlock(b)

	if !strings.Contains(result, "Session started") {
		t.Error("expected system message in output")
	}
}

// ---------------------------------------------------------------------------
// formatDuration
// ---------------------------------------------------------------------------

func TestFormatDuration_Seconds(t *testing.T) {
	result := formatDuration(12 * time.Second)
	if result != "12s" {
		t.Errorf("expected '12s', got %q", result)
	}
}

func TestFormatDuration_Minutes(t *testing.T) {
	result := formatDuration(2*time.Minute + 30*time.Second)
	if result != "2m30s" {
		t.Errorf("expected '2m30s', got %q", result)
	}
}

func TestFormatDuration_SubSecond(t *testing.T) {
	result := formatDuration(100 * time.Millisecond)
	if result != "<1s" {
		t.Errorf("expected '<1s', got %q", result)
	}
}

func TestFormatDuration_ExactMinute(t *testing.T) {
	result := formatDuration(1 * time.Minute)
	if result != "1m0s" {
		t.Errorf("expected '1m0s', got %q", result)
	}
}

// ---------------------------------------------------------------------------
// renderBlocks — integration tests
// ---------------------------------------------------------------------------

func TestRenderBlocks_Empty(t *testing.T) {
	result := renderBlocks(nil, 80, false, "⠋")
	if result != "" {
		t.Errorf("expected empty string for nil blocks, got %q", result)
	}
}

func TestRenderBlocks_MultipleTypes(t *testing.T) {
	blocks := []*agent.DisplayBlock{
		agent.NewSystemBlock("Session started"),
		agent.NewUserInputBlock("scan target"),
		agent.NewAIMessageBlock("Starting scan..."),
		func() *agent.DisplayBlock {
			b := agent.NewCommandBlock("nmap -sV 10.0.0.5")
			b.Output = []string{"22/tcp open ssh", "80/tcp open http"}
			return b
		}(),
		agent.NewMemoryBlock("MEDIUM", "Open SSH port"),
	}

	result := renderBlocks(blocks, 80, false, "⠋")
	stripped := stripANSI(result)

	if !strings.Contains(stripped, "Session started") {
		t.Error("expected system message")
	}
	if !strings.Contains(stripped, "scan target") {
		t.Error("expected user input")
	}
	if !strings.Contains(stripped, "Starting scan...") {
		t.Error("expected AI message")
	}
	if !strings.Contains(stripped, "nmap -sV 10.0.0.5") {
		t.Error("expected command")
	}
	if !strings.Contains(stripped, "22/tcp open ssh") {
		t.Error("expected command output")
	}
	if !strings.Contains(stripped, "MEDIUM") {
		t.Error("expected memory severity")
	}
	if !strings.Contains(stripped, "Open SSH port") {
		t.Error("expected memory title")
	}
}

func TestRenderBlocks_NoSessionHeader(t *testing.T) {
	blocks := []*agent.DisplayBlock{
		agent.NewSystemBlock("Session started"),
	}

	result := renderBlocks(blocks, 80, false, "⠋")

	// New renderer should NOT contain the old session header
	if strings.Contains(result, "═══ Session:") {
		t.Error("new block renderer should NOT contain legacy session header")
	}
}

func TestRenderBlocks_ThinkingThenCommand(t *testing.T) {
	thinking := agent.NewThinkingBlock()
	thinking.ThinkingDone = true
	thinking.ThinkDuration = 3 * time.Second

	cmd := agent.NewCommandBlock("whoami")
	cmd.Output = []string{"root"}

	blocks := []*agent.DisplayBlock{thinking, cmd}
	result := renderBlocks(blocks, 80, false, "⠋")

	if !strings.Contains(result, "Completed in 3s") {
		t.Error("expected thinking completion")
	}
	if !strings.Contains(result, "● whoami") {
		t.Error("expected command block")
	}
	if !strings.Contains(result, "root") {
		t.Error("expected command output")
	}
}

func TestRenderBlocks_SpinnerFramePassedToThinkingAndSubTask(t *testing.T) {
	// 処理中の thinking + subtask の両方にスピナーフレームが渡されることを確認
	blocks := []*agent.DisplayBlock{
		agent.NewThinkingBlock(),
		agent.NewSubTaskBlock("task-1", "Run exploit"),
	}

	result := renderBlocks(blocks, 80, false, "⠹")

	// Both blocks should contain the spinner frame "⠹"
	if !strings.Contains(result, "⠹") {
		t.Errorf("expected spinner frame '⠹' in output for active blocks, got:\n%s", result)
	}
}

// ---------------------------------------------------------------------------
// renderMarkdown — cache tests
// ---------------------------------------------------------------------------

func TestRenderMarkdown_CacheReuse(t *testing.T) {
	// 同じ width で2回呼び出し → 両方成功
	out1, err1 := renderMarkdown("**bold**", 80)
	if err1 != nil {
		t.Fatalf("first call failed: %v", err1)
	}
	out2, err2 := renderMarkdown("*italic*", 80)
	if err2 != nil {
		t.Fatalf("second call failed: %v", err2)
	}
	if out1 == "" || out2 == "" {
		t.Error("expected non-empty output from both calls")
	}
}

func TestRenderMarkdown_DifferentWidths(t *testing.T) {
	// width 80 → width 40 → 出力が異なることを確認（折り返し幅の違い）
	longText := strings.Repeat("word ", 30)
	out80, err := renderMarkdown(longText, 80)
	if err != nil {
		t.Fatalf("width 80 failed: %v", err)
	}
	out40, err := renderMarkdown(longText, 40)
	if err != nil {
		t.Fatalf("width 40 failed: %v", err)
	}
	// 異なる折り返し幅なので出力が異なるはず
	if out80 == out40 {
		t.Error("expected different output for different widths")
	}
}

// ---------------------------------------------------------------------------
// renderBlocks — block cache tests
// ---------------------------------------------------------------------------

func TestBlockCache_CompletedThinking(t *testing.T) {
	b := agent.NewThinkingBlock()
	b.ThinkingDone = true
	b.ThinkDuration = 5 * time.Second
	blocks := []*agent.DisplayBlock{b}

	_ = renderBlocks(blocks, 80, false, "⠋")
	if b.RenderedCache == "" {
		t.Error("expected RenderedCache to be set for completed thinking block")
	}
	if b.CacheWidth != 80 {
		t.Errorf("expected CacheWidth 80, got %d", b.CacheWidth)
	}
}

func TestBlockCache_ActiveThinking(t *testing.T) {
	b := agent.NewThinkingBlock()
	b.ThinkingDone = false
	blocks := []*agent.DisplayBlock{b}

	_ = renderBlocks(blocks, 80, false, "⠋")
	if b.RenderedCache != "" {
		t.Error("expected RenderedCache to be empty for active thinking block")
	}
}

func TestBlockCache_CompletedCommand(t *testing.T) {
	b := agent.NewCommandBlock("echo test")
	b.Output = []string{"test output"}
	b.Completed = true
	blocks := []*agent.DisplayBlock{b}

	_ = renderBlocks(blocks, 80, false, "⠋")
	if b.RenderedCache == "" {
		t.Error("expected RenderedCache to be set for completed command block")
	}
}

func TestBlockCache_ActiveCommand(t *testing.T) {
	b := agent.NewCommandBlock("running...")
	b.Completed = false
	blocks := []*agent.DisplayBlock{b}

	_ = renderBlocks(blocks, 80, false, "⠋")
	if b.RenderedCache != "" {
		t.Error("expected RenderedCache to be empty for active command block")
	}
}

func TestBlockCache_AIMessage(t *testing.T) {
	b := agent.NewAIMessageBlock("Hello world")
	blocks := []*agent.DisplayBlock{b}

	_ = renderBlocks(blocks, 80, false, "⠋")
	if b.RenderedCache == "" {
		t.Error("expected RenderedCache to be set for AI message block")
	}
}

func TestBlockCache_WidthChange(t *testing.T) {
	b := agent.NewAIMessageBlock("Cached text")
	blocks := []*agent.DisplayBlock{b}

	// First render at width 80
	result1 := renderBlocks(blocks, 80, false, "⠋")
	if b.CacheWidth != 80 {
		t.Fatalf("expected CacheWidth 80, got %d", b.CacheWidth)
	}

	// Second render at different width — should re-render
	result2 := renderBlocks(blocks, 40, false, "⠋")
	if b.CacheWidth != 40 {
		t.Errorf("expected CacheWidth updated to 40, got %d", b.CacheWidth)
	}
	// Results may differ due to different wrap widths
	_ = result1
	_ = result2
}

func TestBlockCache_CacheHit(t *testing.T) {
	b := agent.NewSystemBlock("System message")
	blocks := []*agent.DisplayBlock{b}

	// First render — sets cache
	result1 := renderBlocks(blocks, 80, false, "⠋")
	if b.RenderedCache == "" {
		t.Fatal("expected cache to be set after first render")
	}

	// Second render — should use cache (same output)
	result2 := renderBlocks(blocks, 80, false, "⠋")
	if result1 != result2 {
		t.Error("expected identical output from cached render")
	}
}

func TestBlockCache_CompletedSubTask(t *testing.T) {
	b := agent.NewSubTaskBlock("task-1", "Scan ports")
	b.TaskDone = true
	b.TaskDuration = 3 * time.Second
	blocks := []*agent.DisplayBlock{b}

	_ = renderBlocks(blocks, 80, false, "⠋")
	if b.RenderedCache == "" {
		t.Error("expected RenderedCache to be set for completed subtask block")
	}
}

func TestBlockCache_ActiveSubTask(t *testing.T) {
	b := agent.NewSubTaskBlock("task-1", "Running...")
	b.TaskDone = false
	blocks := []*agent.DisplayBlock{b}

	_ = renderBlocks(blocks, 80, false, "⠋")
	if b.RenderedCache != "" {
		t.Error("expected RenderedCache to be empty for active subtask block")
	}
}

func TestBlockCache_MemoryBlock(t *testing.T) {
	b := agent.NewMemoryBlock("HIGH", "SQL Injection")
	blocks := []*agent.DisplayBlock{b}

	_ = renderBlocks(blocks, 80, false, "⠋")
	if b.RenderedCache == "" {
		t.Error("expected RenderedCache to be set for memory block")
	}
}

func TestBlockCache_UserInputBlock(t *testing.T) {
	b := agent.NewUserInputBlock("scan target")
	blocks := []*agent.DisplayBlock{b}

	_ = renderBlocks(blocks, 80, false, "⠋")
	if b.RenderedCache == "" {
		t.Error("expected RenderedCache to be set for user input block")
	}
}

func TestBlockCache_ExpandedChange(t *testing.T) {
	b := agent.NewCommandBlock("ls -la")
	b.Output = []string{"l1", "l2", "l3", "l4", "l5", "l6"}
	b.Completed = true
	blocks := []*agent.DisplayBlock{b}

	// Render with expanded=false
	_ = renderBlocks(blocks, 80, false, "⠋")
	if b.CacheExpanded != false {
		t.Error("expected CacheExpanded=false")
	}
	cachedFolded := b.RenderedCache

	// Render with expanded=true — cache should be invalidated
	_ = renderBlocks(blocks, 80, true, "⠋")
	if b.CacheExpanded != true {
		t.Error("expected CacheExpanded=true after re-render")
	}
	if b.RenderedCache == cachedFolded {
		t.Error("expected different cache for different expanded state")
	}
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

func BenchmarkRenderMarkdown(b *testing.B) {
	text := "# Heading\n\nSome **bold** and *italic* text.\n\n- item 1\n- item 2\n\n```bash\necho hello\n```"
	for i := 0; i < b.N; i++ {
		_, _ = renderMarkdown(text, 80)
	}
}

func BenchmarkRenderBlocks_50Blocks_Cached(b *testing.B) {
	blocks := make([]*agent.DisplayBlock, 50)
	for i := 0; i < 50; i++ {
		switch i % 5 {
		case 0:
			blk := agent.NewCommandBlock("echo test")
			blk.Output = []string{"output line"}
			blk.Completed = true
			blocks[i] = blk
		case 1:
			blk := agent.NewThinkingBlock()
			blk.ThinkingDone = true
			blk.ThinkDuration = 2 * time.Second
			blocks[i] = blk
		case 2:
			blocks[i] = agent.NewAIMessageBlock("Some AI response text here.")
		case 3:
			blocks[i] = agent.NewSystemBlock("System message")
		case 4:
			blk := agent.NewSubTaskBlock("task", "Goal text")
			blk.TaskDone = true
			blk.TaskDuration = 1 * time.Second
			blocks[i] = blk
		}
	}

	// Warm up cache
	_ = renderBlocks(blocks, 80, false, "⠋")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = renderBlocks(blocks, 80, false, "⠋")
	}
}

func BenchmarkRenderBlocks_50Blocks_NoCacheBaseline(b *testing.B) {
	// Create fresh blocks each iteration to avoid cache hits
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		blocks := make([]*agent.DisplayBlock, 50)
		for j := 0; j < 50; j++ {
			switch j % 5 {
			case 0:
				blk := agent.NewCommandBlock("echo test")
				blk.Output = []string{"output line"}
				blk.Completed = true
				blocks[j] = blk
			case 1:
				blk := agent.NewThinkingBlock()
				blk.ThinkingDone = true
				blk.ThinkDuration = 2 * time.Second
				blocks[j] = blk
			case 2:
				blocks[j] = agent.NewAIMessageBlock("Some AI response text here.")
			case 3:
				blocks[j] = agent.NewSystemBlock("System message")
			case 4:
				blk := agent.NewSubTaskBlock("task", "Goal text")
				blk.TaskDone = true
				blk.TaskDuration = 1 * time.Second
				blocks[j] = blk
			}
		}
		_ = renderBlocks(blocks, 80, false, "⠋")
	}
}
