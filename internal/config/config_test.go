package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/0x6d61/pentecter/internal/config"
)

func TestLoad_Valid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := `knowledge:
  - name: hacktricks
    path: "/home/user/hacktricks/src"
  - name: payloads
    path: "/opt/payloads"

blacklist:
  - 'rm\s+-rf\s+/'
  - 'dd\s+if='
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if len(cfg.Knowledge) != 2 {
		t.Fatalf("expected 2 knowledge entries, got %d", len(cfg.Knowledge))
	}
	if cfg.Knowledge[0].Name != "hacktricks" {
		t.Errorf("expected name 'hacktricks', got '%s'", cfg.Knowledge[0].Name)
	}
	if cfg.Knowledge[0].Path != "/home/user/hacktricks/src" {
		t.Errorf("expected path '/home/user/hacktricks/src', got '%s'", cfg.Knowledge[0].Path)
	}
	if len(cfg.Blacklist) != 2 {
		t.Fatalf("expected 2 blacklist patterns, got %d", len(cfg.Blacklist))
	}
	if cfg.Blacklist[0] != `rm\s+-rf\s+/` {
		t.Errorf("unexpected blacklist pattern: %s", cfg.Blacklist[0])
	}
}

func TestLoad_EnvExpansion(t *testing.T) {
	t.Setenv("TEST_CONFIG_HOME", "/home/testuser")
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := `knowledge:
  - name: hacktricks
    path: "${TEST_CONFIG_HOME}/hacktricks/src"
blacklist: []
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.Knowledge[0].Path != "/home/testuser/hacktricks/src" {
		t.Errorf("expected expanded path, got '%s'", cfg.Knowledge[0].Path)
	}
}

func TestLoad_FileNotFound(t *testing.T) {
	cfg, err := config.Load("/nonexistent/path/config.yaml")
	if err != nil {
		t.Fatalf("expected nil error for missing file, got: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil default config")
	}
	if len(cfg.Knowledge) != 0 {
		t.Errorf("expected empty knowledge, got %d", len(cfg.Knowledge))
	}
	if len(cfg.Blacklist) != 0 {
		t.Errorf("expected empty blacklist, got %d", len(cfg.Blacklist))
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(`{{{invalid`), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestLoad_MissingSections(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := `knowledge:
  - name: test
    path: "/test"
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if len(cfg.Knowledge) != 1 {
		t.Errorf("expected 1 knowledge entry, got %d", len(cfg.Knowledge))
	}
	if len(cfg.Blacklist) != 0 {
		t.Errorf("expected 0 blacklist patterns for missing section, got %d", len(cfg.Blacklist))
	}
}
