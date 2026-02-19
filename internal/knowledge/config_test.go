package knowledge_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/0x6d61/pentecter/internal/knowledge"
)

func TestLoadKnowledgeConfig_Valid(t *testing.T) {
	// 正常な YAML ファイルを読み込めること
	dir := t.TempDir()
	path := filepath.Join(dir, "knowledge.yaml")
	content := `knowledge:
  - name: hacktricks
    path: "/home/user/hacktricks/src"
  - name: payloads
    path: "/opt/payloads"
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := knowledge.LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig returned error: %v", err)
	}
	if cfg == nil {
		t.Fatal("LoadConfig returned nil config")
	}
	if len(cfg.Knowledge) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(cfg.Knowledge))
	}

	// 1つ目のエントリ確認
	e := cfg.Knowledge[0]
	if e.Name != "hacktricks" {
		t.Errorf("expected name 'hacktricks', got '%s'", e.Name)
	}
	if e.Path != "/home/user/hacktricks/src" {
		t.Errorf("expected path '/home/user/hacktricks/src', got '%s'", e.Path)
	}

	// 2つ目のエントリ確認
	e2 := cfg.Knowledge[1]
	if e2.Name != "payloads" {
		t.Errorf("expected name 'payloads', got '%s'", e2.Name)
	}
	if e2.Path != "/opt/payloads" {
		t.Errorf("expected path '/opt/payloads', got '%s'", e2.Path)
	}
}

func TestLoadKnowledgeConfig_EnvExpansion(t *testing.T) {
	// ${VAR} が os.Getenv(VAR) に展開されること
	t.Setenv("TEST_KNOWLEDGE_HOME", "/home/testuser")

	dir := t.TempDir()
	path := filepath.Join(dir, "knowledge.yaml")
	content := `knowledge:
  - name: hacktricks
    path: "${TEST_KNOWLEDGE_HOME}/hacktricks/src"
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := knowledge.LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig returned error: %v", err)
	}

	if cfg.Knowledge[0].Path != "/home/testuser/hacktricks/src" {
		t.Errorf("expected expanded path '/home/testuser/hacktricks/src', got '%s'", cfg.Knowledge[0].Path)
	}
}

func TestLoadKnowledgeConfig_EnvExpansion_Undefined(t *testing.T) {
	// 未定義の環境変数は空文字列に展開される
	os.Unsetenv("TEST_KNOWLEDGE_UNDEFINED_CHECK")

	dir := t.TempDir()
	path := filepath.Join(dir, "knowledge.yaml")
	content := `knowledge:
  - name: test
    path: "${TEST_KNOWLEDGE_UNDEFINED_CHECK}/hacktricks/src"
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := knowledge.LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig returned error: %v", err)
	}

	if cfg.Knowledge[0].Path != "/hacktricks/src" {
		t.Errorf("expected '/hacktricks/src' for undefined var, got '%s'", cfg.Knowledge[0].Path)
	}
}

func TestLoadKnowledgeConfig_FileNotFound(t *testing.T) {
	// 存在しないファイルの場合は nil, nil を返す（graceful skip）
	cfg, err := knowledge.LoadConfig("/nonexistent/path/knowledge.yaml")
	if err != nil {
		t.Fatalf("expected nil error for missing file, got: %v", err)
	}
	if cfg != nil {
		t.Fatal("expected nil config for missing file")
	}
}

func TestLoadKnowledgeConfig_InvalidYAML(t *testing.T) {
	// 不正な YAML はエラーを返す
	dir := t.TempDir()
	path := filepath.Join(dir, "knowledge.yaml")
	content := `{{{invalid yaml`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := knowledge.LoadConfig(path)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestLoadKnowledgeConfig_EmptyKnowledge(t *testing.T) {
	// knowledge が空配列の場合も正常に読み込めること
	dir := t.TempDir()
	path := filepath.Join(dir, "knowledge.yaml")
	content := `knowledge: []
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := knowledge.LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig returned error: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if len(cfg.Knowledge) != 0 {
		t.Fatalf("expected 0 entries, got %d", len(cfg.Knowledge))
	}
}
