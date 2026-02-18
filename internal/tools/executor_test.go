package tools_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/0x6d61/pentecter/internal/tools"
)

func TestYAMLExecutor_Execute_StreamsLines(t *testing.T) {
	store := tools.NewLogStore()
	reg := tools.NewRegistry()
	reg.Register(&tools.ToolDef{
		Name:        "echo",
		Binary:      "echo",
		ArgsTemplate: "{message}",
		TimeoutSec:  5,
		Output:      tools.OutputConfig{Strategy: tools.StrategyHeadTail, HeadLines: 5, TailLines: 5},
	})

	exec, ok := reg.Resolve("echo")
	if !ok {
		t.Fatal("echo not found in registry")
	}

	lines, resultCh := exec.Execute(context.Background(), store, map[string]any{
		"message": "hello hybrid",
	})

	var collected []string
	for line := range lines {
		collected = append(collected, line.Content)
	}
	res := <-resultCh

	if res.Err != nil {
		t.Fatalf("Execute error: %v", res.Err)
	}
	if len(collected) == 0 {
		t.Fatal("expected output lines")
	}
	if !containsSubstr(collected, "hello hybrid") {
		t.Errorf("expected 'hello hybrid' in output, got: %v", collected)
	}
}

func TestRegistry_Resolve_FallsBackToYAML(t *testing.T) {
	// MCP サーバーが設定されていないツールは YAML にフォールバックする
	reg := tools.NewRegistry()
	reg.Register(&tools.ToolDef{
		Name:   "echo",
		Binary: "echo",
	})

	exec, ok := reg.Resolve("echo")
	if !ok {
		t.Fatal("echo should be resolvable via YAML fallback")
	}
	if exec == nil {
		t.Fatal("executor should not be nil")
	}
}

func TestRegistry_Resolve_UnknownTool(t *testing.T) {
	reg := tools.NewRegistry()
	_, ok := reg.Resolve("nonexistent_tool_xyz")
	if ok {
		t.Error("expected Resolve to return false for unknown tool")
	}
}

func TestRegistry_LoadMCPConfig_InvalidURL_FallsBackToYAML(t *testing.T) {
	dir := t.TempDir()
	mcpYAML := `
servers:
  - tool: echo
    transport: http
    url: http://localhost:19999/sse
`
	if err := os.WriteFile(filepath.Join(dir, "mcp-servers.yaml"), []byte(mcpYAML), 0o600); err != nil {
		t.Fatal(err)
	}

	reg := tools.NewRegistry()
	reg.Register(&tools.ToolDef{Name: "echo", Binary: "echo"})

	// MCP 設定をロード（接続はしない。起動時は URL 存在確認だけ）
	if err := reg.LoadMCPConfig(filepath.Join(dir, "mcp-servers.yaml")); err != nil {
		t.Fatalf("LoadMCPConfig: %v", err)
	}

	// MCP サーバーが落ちていても YAML にフォールバックできること
	exec, ok := reg.Resolve("echo")
	if !ok {
		t.Fatal("should fallback to YAML when MCP is not reachable")
	}
	if exec == nil {
		t.Fatal("executor should not be nil")
	}

	// 実際に実行して動くことを確認
	store := tools.NewLogStore()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	lines, resultCh := exec.Execute(ctx, store, map[string]any{"_args": []any{"fallback-ok"}})
	for range lines {
	}
	res := <-resultCh
	if res.Err != nil {
		t.Fatalf("fallback execution error: %v", res.Err)
	}
}

func containsSubstr(ss []string, sub string) bool {
	for _, s := range ss {
		if len(s) > 0 && (s == sub || len(s) >= len(sub) && containsStr(s, sub)) {
			return true
		}
	}
	return false
}

func containsStr(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub ||
		func() bool {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
			return false
		}())
}
