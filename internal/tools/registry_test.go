package tools_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/0x6d61/pentecter/internal/tools"
)

func TestRegistry_LoadDir(t *testing.T) {
	dir := t.TempDir()

	// テスト用 YAML を書き込む
	yaml1 := `
name: testtool
binary: echo
description: "テスト用ツール"
tags: [test]
timeout: 10
default_args: ["-n"]
output:
  strategy: head_tail
  head_lines: 10
  tail_lines: 5
`
	if err := os.WriteFile(filepath.Join(dir, "testtool.yaml"), []byte(yaml1), 0o600); err != nil {
		t.Fatal(err)
	}

	r := tools.NewRegistry()
	if err := r.LoadDir(dir); err != nil {
		t.Fatalf("LoadDir: %v", err)
	}

	def, ok := r.Get("testtool")
	if !ok {
		t.Fatal("testtool not found in registry")
	}
	if def.Binary != "echo" {
		t.Errorf("Binary: got %q, want %q", def.Binary, "echo")
	}
	if def.TimeoutSec != 10 {
		t.Errorf("TimeoutSec: got %d, want 10", def.TimeoutSec)
	}
	if len(def.DefaultArgs) != 1 || def.DefaultArgs[0] != "-n" {
		t.Errorf("DefaultArgs: got %v, want [-n]", def.DefaultArgs)
	}
}

func TestRegistry_LoadDir_NonExistentDir(t *testing.T) {
	r := tools.NewRegistry()
	// 存在しないディレクトリはエラーにならない（起動時の柔軟性）
	if err := r.LoadDir("/nonexistent/path/to/tools"); err != nil {
		t.Errorf("LoadDir on missing dir should not error, got: %v", err)
	}
}

func TestRegistry_Register_And_Get(t *testing.T) {
	r := tools.NewRegistry()
	def := &tools.ToolDef{
		Name:   "mytool",
		Binary: "echo",
	}
	r.Register(def)

	got, ok := r.Get("mytool")
	if !ok {
		t.Fatal("mytool not found after Register")
	}
	if got.Binary != "echo" {
		t.Errorf("Binary: got %q, want %q", got.Binary, "echo")
	}
}

func TestRegistry_All(t *testing.T) {
	r := tools.NewRegistry()
	r.Register(&tools.ToolDef{Name: "a", Binary: "echo"})
	r.Register(&tools.ToolDef{Name: "b", Binary: "echo"})

	all := r.All()
	if len(all) != 2 {
		t.Errorf("All(): got %d tools, want 2", len(all))
	}
}
