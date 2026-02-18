package tools_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/0x6d61/pentecter/internal/tools"
)

// echoTool は echo コマンドを使ったテスト用 ToolDef を返す。
func echoTool(msg string) *tools.ToolDef {
	return &tools.ToolDef{
		Name:       "echo",
		Binary:     "echo",
		TimeoutSec: 5,
		DefaultArgs: []string{msg},
		Output: tools.OutputConfig{
			Strategy:  tools.StrategyHeadTail,
			HeadLines: 10,
			TailLines: 5,
		},
	}
}

func TestRunner_Run_StreamsLines(t *testing.T) {
	store := tools.NewLogStore()
	runner := tools.NewRunner(store)

	def := echoTool("hello pentecter")
	lines, result := runner.Run(context.Background(), def, "", nil)

	var collected []tools.OutputLine
	for line := range lines {
		collected = append(collected, line)
	}
	<-result // 完了待ち

	if len(collected) == 0 {
		t.Fatal("expected at least one line from echo")
	}
	if !strings.Contains(collected[0].Content, "hello pentecter") {
		t.Errorf("content: got %q, want to contain 'hello pentecter'", collected[0].Content)
	}
}

func TestRunner_Run_SavesResultToLogStore(t *testing.T) {
	store := tools.NewLogStore()
	runner := tools.NewRunner(store)

	def := echoTool("store test")
	lines, resultCh := runner.Run(context.Background(), def, "10.0.0.1", nil)

	for range lines {
	}
	res := <-resultCh

	if res == nil {
		t.Fatal("result is nil")
	}
	if res.ToolName != "echo" {
		t.Errorf("ToolName: got %q, want echo", res.ToolName)
	}
	if res.Target != "10.0.0.1" {
		t.Errorf("Target: got %q, want 10.0.0.1", res.Target)
	}

	// LogStore に保存されているか確認
	stored, ok := store.Get(res.ID)
	if !ok {
		t.Fatal("result not found in LogStore")
	}
	if stored.ID != res.ID {
		t.Errorf("stored ID mismatch: got %q, want %q", stored.ID, res.ID)
	}
}

func TestRunner_Run_TruncatedOutputIsNonEmpty(t *testing.T) {
	store := tools.NewLogStore()
	runner := tools.NewRunner(store)

	def := echoTool("truncation test line")
	lines, resultCh := runner.Run(context.Background(), def, "", nil)

	for range lines {
	}
	res := <-resultCh

	if res.Truncated == "" {
		t.Error("Truncated output should not be empty")
	}
}

func TestRunner_Run_InvalidBinary_ReturnsError(t *testing.T) {
	store := tools.NewLogStore()
	runner := tools.NewRunner(store)

	def := &tools.ToolDef{
		Name:       "notabinary",
		Binary:     "this_tool_does_not_exist_xyz",
		TimeoutSec: 5,
	}
	lines, resultCh := runner.Run(context.Background(), def, "", nil)

	for range lines {
	}
	res := <-resultCh

	if res.Err == nil {
		t.Error("expected error for nonexistent binary, got nil")
	}
}

func TestRunner_Run_PathTraversal_ReturnsError(t *testing.T) {
	store := tools.NewLogStore()
	runner := tools.NewRunner(store)

	def := &tools.ToolDef{
		Name:       "evil",
		Binary:     "../../bin/sh", // パストラバーサル試行
		TimeoutSec: 5,
	}
	lines, resultCh := runner.Run(context.Background(), def, "", nil)

	for range lines {
	}
	res := <-resultCh

	if res.Err == nil {
		t.Error("path traversal binary should return error")
	}
}

func TestLogStore_FullText(t *testing.T) {
	store := tools.NewLogStore()
	runner := tools.NewRunner(store)

	def := echoTool("fulltext check")
	lines, resultCh := runner.Run(context.Background(), def, "10.0.0.5", nil)

	for range lines {
	}
	res := <-resultCh

	text, ok := store.FullText(res.ID)
	if !ok {
		t.Fatal("FullText: result not found")
	}
	if !strings.Contains(text, "echo") {
		t.Errorf("FullText should contain tool name, got: %q", text)
	}
	if !strings.Contains(text, "fulltext check") {
		t.Errorf("FullText should contain output content")
	}
}

func TestLogStore_ForTarget(t *testing.T) {
	store := tools.NewLogStore()
	runner := tools.NewRunner(store)

	ctx := context.Background()
	target := "10.0.0.99"

	for i := 0; i < 3; i++ {
		def := echoTool("run")
		lines, resultCh := runner.Run(ctx, def, target, nil)
		for range lines {
		}
		<-resultCh
		time.Sleep(time.Millisecond) // ID の一意性のため
	}

	results := store.ForTarget(target)
	if len(results) != 3 {
		t.Errorf("ForTarget: got %d results, want 3", len(results))
	}
}
