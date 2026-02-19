package mcp

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig_ValidYAML(t *testing.T) {
	// 正常な YAML ファイルを読み込めること
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp.yaml")
	content := `servers:
  - name: playwright
    command: npx
    args: ["@playwright/mcp@latest"]
    env:
      API_KEY: "test-key"
    proposal_required: true
  - name: filesystem
    command: node
    args: ["server.js", "/tmp"]
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig returned error: %v", err)
	}
	if cfg == nil {
		t.Fatal("LoadConfig returned nil config")
	}
	if len(cfg.Servers) != 2 {
		t.Fatalf("expected 2 servers, got %d", len(cfg.Servers))
	}

	// 1つ目のサーバー確認
	s := cfg.Servers[0]
	if s.Name != "playwright" {
		t.Errorf("expected name 'playwright', got '%s'", s.Name)
	}
	if s.Command != "npx" {
		t.Errorf("expected command 'npx', got '%s'", s.Command)
	}
	if len(s.Args) != 1 || s.Args[0] != "@playwright/mcp@latest" {
		t.Errorf("unexpected args: %v", s.Args)
	}
	if s.Env["API_KEY"] != "test-key" {
		t.Errorf("expected env API_KEY='test-key', got '%s'", s.Env["API_KEY"])
	}
	if s.ProposalRequired == nil || !*s.ProposalRequired {
		t.Error("expected proposal_required=true")
	}

	// 2つ目のサーバー確認
	s2 := cfg.Servers[1]
	if s2.Name != "filesystem" {
		t.Errorf("expected name 'filesystem', got '%s'", s2.Name)
	}
	if s2.ProposalRequired != nil {
		t.Errorf("expected proposal_required=nil, got %v", *s2.ProposalRequired)
	}
}

func TestLoadConfig_EnvVarExpansion(t *testing.T) {
	// ${VAR} が os.Getenv(VAR) に展開されること
	t.Setenv("TEST_MCP_SECRET", "expanded-value")

	dir := t.TempDir()
	path := filepath.Join(dir, "mcp.yaml")
	content := `servers:
  - name: test-server
    command: echo
    args: []
    env:
      SECRET: "${TEST_MCP_SECRET}"
      PLAIN: "no-expansion"
      MIXED: "prefix-${TEST_MCP_SECRET}-suffix"
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig returned error: %v", err)
	}

	env := cfg.Servers[0].Env
	if env["SECRET"] != "expanded-value" {
		t.Errorf("expected 'expanded-value', got '%s'", env["SECRET"])
	}
	if env["PLAIN"] != "no-expansion" {
		t.Errorf("expected 'no-expansion', got '%s'", env["PLAIN"])
	}
	if env["MIXED"] != "prefix-expanded-value-suffix" {
		t.Errorf("expected 'prefix-expanded-value-suffix', got '%s'", env["MIXED"])
	}
}

func TestLoadConfig_EnvVarExpansion_Undefined(t *testing.T) {
	// 未定義の環境変数は空文字列に展開される
	t.Setenv("TEST_MCP_UNDEFINED_CHECK", "") // 明示的にクリア
	os.Unsetenv("TEST_MCP_UNDEFINED_CHECK")

	dir := t.TempDir()
	path := filepath.Join(dir, "mcp.yaml")
	content := `servers:
  - name: test-server
    command: echo
    args: []
    env:
      MISSING: "${TEST_MCP_UNDEFINED_CHECK}"
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig returned error: %v", err)
	}

	if cfg.Servers[0].Env["MISSING"] != "" {
		t.Errorf("expected empty string for undefined var, got '%s'", cfg.Servers[0].Env["MISSING"])
	}
}

func TestLoadConfig_FileNotFound(t *testing.T) {
	// 存在しないファイルの場合は nil, nil を返す（graceful skip）
	cfg, err := LoadConfig("/nonexistent/path/mcp.yaml")
	if err != nil {
		t.Fatalf("expected nil error for missing file, got: %v", err)
	}
	if cfg != nil {
		t.Fatal("expected nil config for missing file")
	}
}

func TestLoadConfig_InvalidYAML(t *testing.T) {
	// 不正な YAML はエラーを返す
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp.yaml")
	content := `{{{invalid yaml`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestLoadConfig_EmptyServers(t *testing.T) {
	// servers が空配列の場合も正常に読み込めること
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp.yaml")
	content := `servers: []
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig returned error: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if len(cfg.Servers) != 0 {
		t.Fatalf("expected 0 servers, got %d", len(cfg.Servers))
	}
}
