package agent

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/0x6d61/pentecter/internal/memory"
	"github.com/0x6d61/pentecter/internal/tools"
	"github.com/0x6d61/pentecter/pkg/schema"
)

func TestIsFailedOutput(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   bool
	}{
		// 既存パターン
		{"empty output", "", true},
		{"host down", "Nmap done: 1 IP address (0 hosts up) scanned in 1.85 seconds", true},
		{"host seems down", "Note: Host seems down.", true},
		{"connection refused", "curl: (7) Failed to connect: Connection refused", true},
		{"no route", "No route to host", true},
		{"network unreachable", "connect: Network is unreachable", true},
		{"name resolution", "Name or service not known", true},
		{"error prefix", "Error: exec failed", true},
		{"successful nmap", "PORT   STATE SERVICE\n22/tcp open  ssh\n80/tcp open  http", false},
		{"successful curl", "HTTP/1.1 200 OK\nContent-Type: text/html", false},
		{"partial output", "Starting Nmap 7.95\nSome results here", false},
		// 新パターン: プログラムエラー
		{"SyntaxError", "  File \"<string>\", line 1\nSyntaxError: invalid syntax", true},
		{"command not found", "bash: nmap: command not found", true},
		{"No such file or directory", "cat: /etc/secret: No such file or directory", true},
		{"Permission denied", "bash: /usr/sbin/nmap: Permission denied", true},
		{"Traceback", "Traceback (most recent call last):\n  File ...", true},
		{"ModuleNotFoundError", "ModuleNotFoundError: No module named 'requests'", true},
		{"ImportError", "ImportError: cannot import name 'foo'", true},
		{"Go panic", "panic: runtime error: index out of range", true},
		{"NameError python", "NameError: name 'x' is not defined", true},
		{"segfault", "Segmentation fault (core dumped)", true},
		// 偽陽性の確認
		{"normal nmap output", "PORT   STATE SERVICE\n80/tcp open  http\n443/tcp open  https", false},
		{"normal ls output", "bin  etc  home  lib  usr  var", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isFailedOutput(tt.output)
			if got != tt.want {
				t.Errorf("isFailedOutput(%q) = %v, want %v", tt.output, got, tt.want)
			}
		})
	}
}

func TestContainsCI(t *testing.T) {
	tests := []struct {
		s, sub string
		want   bool
	}{
		{"Hello World", "hello", true},
		{"Connection Refused", "connection refused", true},
		{"foo", "bar", false},
		{"", "", true},
		{"short", "longer string", false},
	}

	for _, tt := range tests {
		t.Run(tt.s+"_"+tt.sub, func(t *testing.T) {
			got := containsCI(tt.s, tt.sub)
			if got != tt.want {
				t.Errorf("containsCI(%q, %q) = %v, want %v", tt.s, tt.sub, got, tt.want)
			}
		})
	}
}

func TestBuildCommandSummary(t *testing.T) {
	tests := []struct {
		name     string
		exitCode int
		output   string
		wantSub  string // 結果に含まれるべき部分文字列
	}{
		{
			name:     "success exit 0",
			exitCode: 0,
			output:   "line1\nline2\nline3",
			wantSub:  "exit 0",
		},
		{
			name:     "failure exit 1",
			exitCode: 1,
			output:   "SyntaxError: invalid syntax",
			wantSub:  "exit 1",
		},
		{
			name:     "failure exit 2 with error",
			exitCode: 2,
			output:   "bash: nmap: command not found",
			wantSub:  "command not found",
		},
		{
			name:     "success with many lines",
			exitCode: 0,
			output:   "1\n2\n3\n4\n5\n6\n7\n8\n9\n10\n11\n12",
			wantSub:  "12 lines",
		},
		{
			name:     "empty output",
			exitCode: 0,
			output:   "",
			wantSub:  "exit 0",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildCommandSummary(tt.exitCode, tt.output)
			if got == "" {
				t.Error("buildCommandSummary returned empty string")
			}
			if !containsCI(got, tt.wantSub) {
				t.Errorf("buildCommandSummary(%d, %q) = %q, want substring %q",
					tt.exitCode, tt.output, got, tt.wantSub)
			}
		})
	}
}

func TestEvaluateResult_ExitCodeNonZero(t *testing.T) {
	evCh := make(chan Event, 32)
	l := &Loop{
		target:         NewTarget(1, "10.0.0.1"),
		lastExitCode:   1,
		lastToolOutput: "some output",
		events:         evCh,
	}
	l.evaluateResult(context.Background())
	if l.consecutiveFailures != 1 {
		t.Errorf("consecutiveFailures = %d, want 1 (exit code != 0 should count as failure)", l.consecutiveFailures)
	}
}

func TestEvaluateResult_ExitCodeZero_SuccessfulOutput(t *testing.T) {
	evCh := make(chan Event, 32)
	l := &Loop{
		target:         NewTarget(1, "10.0.0.1"),
		lastExitCode:   0,
		lastToolOutput: "PORT 80/tcp open http",
		events:         evCh,
	}
	l.evaluateResult(context.Background())
	if l.consecutiveFailures != 0 {
		t.Errorf("consecutiveFailures = %d, want 0 (exit 0 + good output = success)", l.consecutiveFailures)
	}
}

func TestBuildHistory_WithSummary(t *testing.T) {
	evCh := make(chan Event, 32)
	l := &Loop{
		target: NewTarget(1, "10.0.0.1"),
		events: evCh,
		history: []commandEntry{
			{Command: "nmap -sV 10.0.0.5", ExitCode: 0, Summary: "PORT 22/tcp open ssh"},
			{Command: "curl http://10.0.0.5", ExitCode: 0, Summary: "HTTP/1.1 200 OK"},
			{Command: "nikto -h 10.0.0.5", ExitCode: 1, Summary: ""},
		},
	}
	got := l.buildHistory()

	// エントリ1: summary あり → "exit 0: PORT 22/tcp open ssh"
	if !containsCI(got, "exit 0: PORT 22/tcp open ssh") {
		t.Errorf("expected summary in history entry 1, got:\n%s", got)
	}
	// エントリ2: summary あり → "exit 0: HTTP/1.1 200 OK"
	if !containsCI(got, "exit 0: HTTP/1.1 200 OK") {
		t.Errorf("expected summary in history entry 2, got:\n%s", got)
	}
	// エントリ3: summary なし → "exit 1" のみ（コロンなし）
	if containsCI(got, "exit 1:") {
		t.Errorf("entry 3 has empty summary, should not have colon after exit code, got:\n%s", got)
	}
	if !containsCI(got, "exit 1") {
		t.Errorf("expected exit code 1 in history entry 3, got:\n%s", got)
	}
}

func TestBuildHistory_EmptySummary_NoColon(t *testing.T) {
	evCh := make(chan Event, 32)
	l := &Loop{
		target: NewTarget(1, "10.0.0.1"),
		events: evCh,
		history: []commandEntry{
			{Command: "whoami", ExitCode: 0, Summary: ""},
		},
	}
	got := l.buildHistory()

	// summary が空なら "exit 0" のみで、コロンは付かない
	if containsCI(got, "exit 0:") {
		t.Errorf("empty summary should not produce colon, got:\n%s", got)
	}
}

// =============================================================================
// recordMemory 直接テスト（package agent 内部） (#90)
// =============================================================================

func TestRecordMemory_Nil(t *testing.T) {
	evCh := make(chan Event, 32)
	l := &Loop{
		target: NewTarget(1, "10.0.0.1"),
		events: evCh,
	}
	// nil を渡してもパニックしない
	l.recordMemory(nil)
	// イベントは発行されない
	select {
	case e := <-evCh:
		t.Errorf("expected no event for nil memory, got: %v", e)
	default:
	}
}

func TestRecordMemory_WithoutStore(t *testing.T) {
	evCh := make(chan Event, 32)
	l := &Loop{
		target:      NewTarget(1, "10.0.0.1"),
		events:      evCh,
		memoryStore: nil,
	}

	m := &schema.Memory{
		Type:        schema.MemoryVulnerability,
		Title:       "XSS",
		Description: "reflected XSS in /search",
		Severity:    "high",
	}
	l.recordMemory(m)

	// ログイベントが発行されること
	select {
	case e := <-evCh:
		if e.Type != EventLog {
			t.Errorf("expected EventLog, got %v", e.Type)
		}
		if !strings.Contains(e.Message, "XSS") {
			t.Errorf("expected 'XSS' in message, got: %s", e.Message)
		}
	default:
		t.Error("expected an event to be emitted")
	}
}

func TestRecordMemory_WithStore(t *testing.T) {
	evCh := make(chan Event, 32)
	memDir := t.TempDir()
	memStore := memory.NewStore(memDir)

	l := &Loop{
		target:      NewTarget(1, "10.0.0.1"),
		events:      evCh,
		memoryStore: memStore,
	}

	m := &schema.Memory{
		Type:        schema.MemoryCredential,
		Title:       "SSH key",
		Description: "found private key in /home/user/.ssh/id_rsa",
		Severity:    "critical",
	}
	l.recordMemory(m)

	// ログイベントが発行されること
	select {
	case e := <-evCh:
		if !strings.Contains(e.Message, "SSH key") {
			t.Errorf("expected 'SSH key' in message, got: %s", e.Message)
		}
	default:
		t.Error("expected an event to be emitted")
	}

	// Memory Store に永続化されていること
	content := memStore.Read("10.0.0.1")
	if !strings.Contains(content, "SSH key") {
		t.Errorf("expected memory content to contain 'SSH key', got: %s", content)
	}
}

// =============================================================================
// streamAndCollect 直接テスト（package agent 内部） (#90)
// =============================================================================

func TestStreamAndCollect_SuccessfulResult(t *testing.T) {
	evCh := make(chan Event, 64)
	l := &Loop{
		target:       NewTarget(1, "10.0.0.1"),
		events:       evCh,
		lastCommand:  "echo test",
		cmdStartTime: time.Now(),
	}

	linesCh := make(chan tools.OutputLine, 10)
	resultCh := make(chan *tools.ToolResult, 1)

	linesCh <- tools.OutputLine{Time: time.Now(), Content: "hello", IsError: false}
	linesCh <- tools.OutputLine{Time: time.Now(), Content: "", IsError: false} // 空行（skip される）
	linesCh <- tools.OutputLine{Time: time.Now(), Content: "world", IsError: false}
	close(linesCh)

	resultCh <- &tools.ToolResult{
		ToolName:   "echo",
		ExitCode:   0,
		Truncated:  "hello\nworld",
		Entities:   []tools.Entity{{Type: tools.EntityPort, Value: "80", Context: "open port"}},
		StartedAt:  time.Now(),
		FinishedAt: time.Now(),
	}

	ctx := t.Context()
	l.streamAndCollect(ctx, linesCh, resultCh)

	// lastToolOutput が設定されること
	if l.lastToolOutput != "hello\nworld" {
		t.Errorf("lastToolOutput: got %q, want %q", l.lastToolOutput, "hello\nworld")
	}
	// lastExitCode が設定されること
	if l.lastExitCode != 0 {
		t.Errorf("lastExitCode: got %d, want 0", l.lastExitCode)
	}
	// history にエントリが追加されること
	if len(l.history) != 1 {
		t.Fatalf("history len: got %d, want 1", len(l.history))
	}
	if l.history[0].Command != "echo test" {
		t.Errorf("history[0].Command: got %q, want %q", l.history[0].Command, "echo test")
	}
	// Entities が Target に追加されること
	entities := l.target.SnapshotEntities()
	found := false
	for _, e := range entities {
		if e.Type == tools.EntityPort && e.Value == "80" {
			found = true
		}
	}
	if !found {
		t.Error("expected Entity port:80 to be added to target")
	}
}

func TestStreamAndCollect_ErrorResult(t *testing.T) {
	evCh := make(chan Event, 64)
	l := &Loop{
		target:       NewTarget(1, "10.0.0.1"),
		events:       evCh,
		lastCommand:  "failing-cmd",
		cmdStartTime: time.Now(),
	}

	linesCh := make(chan tools.OutputLine, 10)
	resultCh := make(chan *tools.ToolResult, 1)

	close(linesCh) // 出力なし

	resultCh <- &tools.ToolResult{
		ToolName:   "failing-cmd",
		ExitCode:   1,
		Truncated:  "",
		Err:        fmt.Errorf("exec failed: command not found"),
		StartedAt:  time.Now(),
		FinishedAt: time.Now(),
	}

	ctx := t.Context()
	l.streamAndCollect(ctx, linesCh, resultCh)

	// Err がある場合は "Error: ..." が lastToolOutput に設定される
	if !strings.Contains(l.lastToolOutput, "Error:") {
		t.Errorf("lastToolOutput should contain 'Error:', got: %q", l.lastToolOutput)
	}
	if !strings.Contains(l.lastToolOutput, "exec failed") {
		t.Errorf("lastToolOutput should contain error message, got: %q", l.lastToolOutput)
	}
}

func TestStreamAndCollect_HistoryTruncatedSummary(t *testing.T) {
	evCh := make(chan Event, 64)
	l := &Loop{
		target:       NewTarget(1, "10.0.0.1"),
		events:       evCh,
		lastCommand:  "long-output-cmd",
		cmdStartTime: time.Now(),
	}

	linesCh := make(chan tools.OutputLine, 10)
	resultCh := make(chan *tools.ToolResult, 1)

	close(linesCh)

	longOutput := strings.Repeat("X", 300)
	resultCh <- &tools.ToolResult{
		ToolName:   "long-output-cmd",
		ExitCode:   0,
		Truncated:  longOutput,
		StartedAt:  time.Now(),
		FinishedAt: time.Now(),
	}

	ctx := t.Context()
	l.streamAndCollect(ctx, linesCh, resultCh)

	// history の Summary が 200 文字に切り捨てられること
	if len(l.history) != 1 {
		t.Fatalf("history len: got %d, want 1", len(l.history))
	}
	if len(l.history[0].Summary) != 200 {
		t.Errorf("history[0].Summary len: got %d, want 200", len(l.history[0].Summary))
	}
}

func TestStreamAndCollect_HistoryCap(t *testing.T) {
	evCh := make(chan Event, 256)
	l := &Loop{
		target:       NewTarget(1, "10.0.0.1"),
		events:       evCh,
		cmdStartTime: time.Now(),
	}

	// 12 エントリを追加
	for i := 0; i < 12; i++ {
		linesCh := make(chan tools.OutputLine)
		resultCh := make(chan *tools.ToolResult, 1)
		close(linesCh)

		l.lastCommand = strings.Repeat("a", i+1) // ユニークなコマンド名
		resultCh <- &tools.ToolResult{
			ToolName:   "cmd",
			ExitCode:   0,
			Truncated:  "output",
			StartedAt:  time.Now(),
			FinishedAt: time.Now(),
		}

		ctx := t.Context()
		l.streamAndCollect(ctx, linesCh, resultCh)
	}

	// history は最大10件
	if len(l.history) != 10 {
		t.Errorf("history len: got %d, want 10 (cap)", len(l.history))
	}
	// 最古のエントリ（長さ1の "a"）は削除されているはず
	if l.history[0].Command == "a" {
		t.Error("oldest entry should have been evicted")
	}
}

// =============================================================================
// buildHistory テスト: 5件超の history (#90)
// =============================================================================

func TestBuildHistory_MoreThan5_ShowsLast5(t *testing.T) {
	evCh := make(chan Event, 32)
	entries := make([]commandEntry, 8)
	for i := 0; i < 8; i++ {
		entries[i] = commandEntry{
			Command:  strings.Repeat("c", i+1),
			ExitCode: 0,
			Summary:  "ok",
		}
	}
	l := &Loop{
		target:  NewTarget(1, "10.0.0.1"),
		events:  evCh,
		history: entries,
	}
	got := l.buildHistory()

	// 最新5件のみ表示（entries[3]〜entries[7]）
	// entries[0]（"c"）は最古なので表示されないはず
	// ただし部分一致するため、最短コマンド "c" 単独では判定できない
	// entries[2]（"ccc"）が表示されないことで、最古3件が除外されていることを間接確認
	lines := strings.Split(strings.TrimSpace(got), "\n")
	if len(lines) != 5 {
		t.Errorf("expected 5 history lines, got %d:\n%s", len(lines), got)
	}
	// 最新のエントリ entries[7]（"cccccccc"）は必ず含まれる
	if !strings.Contains(got, "cccccccc") {
		t.Errorf("expected latest entry in history, got:\n%s", got)
	}
	// 5行しかないことを確認（番号 1.〜5.）
	lineCount := strings.Count(got, "\n")
	if lineCount != 5 {
		t.Errorf("expected 5 lines in history output, got %d lines:\n%s", lineCount, got)
	}
}

// =============================================================================
// buildReconQueue / buildMemory テスト (#90)
// =============================================================================

func TestBuildMemory_NilStore(t *testing.T) {
	l := &Loop{
		target:      NewTarget(1, "10.0.0.1"),
		events:      make(chan Event, 32),
		memoryStore: nil,
	}
	got := l.buildMemory()
	if got != "" {
		t.Errorf("buildMemory with nil store should return empty, got: %q", got)
	}
}

func TestBuildMemory_WithStore(t *testing.T) {
	memDir := t.TempDir()
	memStore := memory.NewStore(memDir)
	// 事前にメモリを記録
	_ = memStore.Record("10.0.0.1", &schema.Memory{
		Type:        schema.MemoryVulnerability,
		Title:       "Test Vuln",
		Description: "test description",
		Severity:    "high",
	})

	l := &Loop{
		target:      NewTarget(1, "10.0.0.1"),
		events:      make(chan Event, 32),
		memoryStore: memStore,
	}
	got := l.buildMemory()
	if !strings.Contains(got, "Test Vuln") {
		t.Errorf("buildMemory should contain recorded memory, got: %q", got)
	}
}

func TestBuildReconIntel_NilTree(t *testing.T) {
	l := &Loop{
		target:    NewTarget(1, "10.0.0.1"),
		events:    make(chan Event, 32),
		reconTree: nil,
	}
	got := l.buildReconQueue()
	if got != "" {
		t.Errorf("buildReconQueue with nil tree should return empty, got: %q", got)
	}
}

func TestBuildSnapshot_JSONFormat(t *testing.T) {
	l := &Loop{
		target: NewTarget(1, "10.0.0.1"),
		events: make(chan Event, 32),
	}
	got := l.buildSnapshot()
	if !strings.Contains(got, "10.0.0.1") {
		t.Errorf("buildSnapshot should contain host, got: %q", got)
	}
	if !strings.Contains(got, "host") {
		t.Errorf("buildSnapshot should contain 'host' key, got: %q", got)
	}
}

// =============================================================================
// evaluateResult: 連続失敗カウント (#90)
// =============================================================================

func TestEvaluateResult_ConsecutiveFailures_Reset(t *testing.T) {
	evCh := make(chan Event, 32)
	l := &Loop{
		target:              NewTarget(1, "10.0.0.1"),
		lastExitCode:        1,
		lastToolOutput:      "some error",
		consecutiveFailures: 2,
		events:              evCh,
	}
	l.evaluateResult(context.Background())
	if l.consecutiveFailures != 3 {
		t.Errorf("consecutiveFailures: got %d, want 3", l.consecutiveFailures)
	}

	// 成功でリセット
	l.lastExitCode = 0
	l.lastToolOutput = "PORT 80 open"
	l.evaluateResult(context.Background())
	if l.consecutiveFailures != 0 {
		t.Errorf("consecutiveFailures after success: got %d, want 0", l.consecutiveFailures)
	}
}

func TestEvaluateResult_SignalB_FailedOutputPattern(t *testing.T) {
	// exit code 0 でも出力パターンが failure → 失敗カウント増加
	evCh := make(chan Event, 32)
	l := &Loop{
		target:         NewTarget(1, "10.0.0.1"),
		lastExitCode:   0,
		lastToolOutput: "0 hosts up", // Signal B: failure pattern
		events:         evCh,
	}
	l.evaluateResult(context.Background())
	if l.consecutiveFailures != 1 {
		t.Errorf("consecutiveFailures: got %d, want 1 (Signal B should detect failure)", l.consecutiveFailures)
	}
}

func TestEvaluateResult_EmptyOutput_Failure(t *testing.T) {
	// 空出力 → isFailedOutput returns true → 失敗
	evCh := make(chan Event, 32)
	l := &Loop{
		target:         NewTarget(1, "10.0.0.1"),
		lastExitCode:   0,
		lastToolOutput: "",
		events:         evCh,
	}
	l.evaluateResult(context.Background())
	if l.consecutiveFailures != 1 {
		t.Errorf("consecutiveFailures: got %d, want 1 (empty output = failure)", l.consecutiveFailures)
	}
}

func TestIsWebReconCommand(t *testing.T) {
	tests := []struct {
		name string
		cmd  string
		want bool
	}{
		{"ffuf command", "ffuf -w wordlist -u http://10.10.11.100/FUZZ", true},
		{"dirb command", "dirb http://10.10.11.100/", true},
		{"gobuster command", "gobuster dir -u http://10.10.11.100/ -w wordlist", true},
		{"nikto command", "nikto -h 10.10.11.100", true},
		{"nmap command", "nmap -sV 10.10.11.100", false},
		{"curl command", "curl http://10.10.11.100/", false},
		{"uppercase FFUF", "FFUF -w wordlist -u http://10.10.11.100/FUZZ", true},
		{"path to ffuf", "/usr/bin/ffuf -w wordlist -u http://10.10.11.100/FUZZ", true},
		{"empty command", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isWebReconCommand(tt.cmd)
			if got != tt.want {
				t.Errorf("isWebReconCommand(%q) = %v, want %v", tt.cmd, got, tt.want)
			}
		})
	}
}

