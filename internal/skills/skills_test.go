package skills_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/0x6d61/pentecter/internal/skills"
)

func TestRegistry_Load(t *testing.T) {
	dir := t.TempDir()

	md := `---
name: web-recon
description: "Web app initial recon"
---

Perform web application reconnaissance.
Steps: nmap → nikto → wpscan
`
	if err := os.WriteFile(filepath.Join(dir, "web-recon.md"), []byte(md), 0o600); err != nil {
		t.Fatal(err)
	}

	reg := skills.NewRegistry()
	if err := reg.LoadDir(dir); err != nil {
		t.Fatalf("LoadDir: %v", err)
	}

	sk, ok := reg.Get("web-recon")
	if !ok {
		t.Fatal("web-recon not found")
	}
	if sk.Name != "web-recon" {
		t.Errorf("Name: got %q", sk.Name)
	}
	if sk.Prompt == "" {
		t.Error("Prompt should not be empty")
	}
}

func TestRegistry_Invoke_AddsPromptToContext(t *testing.T) {
	dir := t.TempDir()

	md := "---\nname: sqli\ndescription: \"SQLi check\"\n---\n\nTest for SQL injection vulnerabilities on the target."
	if err := os.WriteFile(filepath.Join(dir, "sqli.md"), []byte(md), 0o600); err != nil {
		t.Fatal(err)
	}

	reg := skills.NewRegistry()
	_ = reg.LoadDir(dir)

	// /sqli というユーザー入力からスキルを検出・展開
	expanded := reg.Expand("/sqli")
	if expanded == "" {
		t.Error("Expand('/sqli') should return skill prompt")
	}
	if expanded != "Test for SQL injection vulnerabilities on the target." {
		t.Errorf("Expand: got %q", expanded)
	}
}

func TestRegistry_Expand_NonSkill_ReturnsOriginal(t *testing.T) {
	reg := skills.NewRegistry()
	input := "focus on port 445 only"
	got := reg.Expand(input)
	if got != input {
		t.Errorf("Non-skill input should be returned as-is: got %q", got)
	}
}

func TestRegistry_LoadDir_Missing_NoError(t *testing.T) {
	reg := skills.NewRegistry()
	err := reg.LoadDir("/nonexistent/skills/dir")
	if err != nil {
		t.Errorf("Missing dir should not error: %v", err)
	}
}

// --- parseYAMLSkill テスト ---

func TestRegistry_LoadDir_YAMLSkill(t *testing.T) {
	dir := t.TempDir()

	yamlContent := `name: sqli
description: "SQLi check"
prompt: "Test for SQL injection"
`
	if err := os.WriteFile(filepath.Join(dir, "sqli.yaml"), []byte(yamlContent), 0o600); err != nil {
		t.Fatal(err)
	}

	reg := skills.NewRegistry()
	if err := reg.LoadDir(dir); err != nil {
		t.Fatalf("LoadDir: %v", err)
	}

	sk, ok := reg.Get("sqli")
	if !ok {
		t.Fatal("sqli skill not found after loading YAML file")
	}
	if sk.Name != "sqli" {
		t.Errorf("Name: got %q, want %q", sk.Name, "sqli")
	}
	if sk.Description != "SQLi check" {
		t.Errorf("Description: got %q, want %q", sk.Description, "SQLi check")
	}
	if sk.Prompt != "Test for SQL injection" {
		t.Errorf("Prompt: got %q, want %q", sk.Prompt, "Test for SQL injection")
	}
}

func TestRegistry_LoadDir_YAMLSkill_InvalidYAML(t *testing.T) {
	dir := t.TempDir()

	// 不正な YAML（パースエラーになるはず）
	if err := os.WriteFile(filepath.Join(dir, "bad.yaml"), []byte(":::invalid:::yaml"), 0o600); err != nil {
		t.Fatal(err)
	}

	reg := skills.NewRegistry()
	if err := reg.LoadDir(dir); err != nil {
		t.Fatalf("LoadDir should not return error for invalid YAML: %v", err)
	}

	// 不正な YAML ファイルはスキップされ、スキルは登録されない
	all := reg.All()
	if len(all) != 0 {
		t.Errorf("expected 0 skills for invalid YAML, got %d", len(all))
	}
}

func TestRegistry_LoadDir_YAMLSkill_EmptyName(t *testing.T) {
	dir := t.TempDir()

	// name が空の YAML はスキップされるべき
	yamlContent := `name: ""
description: "No name"
prompt: "Some prompt"
`
	if err := os.WriteFile(filepath.Join(dir, "noname.yaml"), []byte(yamlContent), 0o600); err != nil {
		t.Fatal(err)
	}

	reg := skills.NewRegistry()
	_ = reg.LoadDir(dir)

	all := reg.All()
	if len(all) != 0 {
		t.Errorf("expected 0 skills for empty-name YAML, got %d", len(all))
	}
}

// --- All テスト ---

func TestRegistry_All(t *testing.T) {
	dir := t.TempDir()

	// MD スキルと YAML スキルを両方ロード
	md := "---\nname: recon\ndescription: \"Recon\"\n---\n\nRecon prompt."
	if err := os.WriteFile(filepath.Join(dir, "recon.md"), []byte(md), 0o600); err != nil {
		t.Fatal(err)
	}

	yamlContent := "name: exploit\ndescription: \"Exploit\"\nprompt: \"Exploit prompt.\"\n"
	if err := os.WriteFile(filepath.Join(dir, "exploit.yaml"), []byte(yamlContent), 0o600); err != nil {
		t.Fatal(err)
	}

	reg := skills.NewRegistry()
	if err := reg.LoadDir(dir); err != nil {
		t.Fatalf("LoadDir: %v", err)
	}

	all := reg.All()
	if len(all) != 2 {
		t.Fatalf("All(): got %d skills, want 2", len(all))
	}

	// 名前でマップに変換して検証
	names := make(map[string]bool)
	for _, sk := range all {
		names[sk.Name] = true
	}
	if !names["recon"] {
		t.Error("All() should contain 'recon'")
	}
	if !names["exploit"] {
		t.Error("All() should contain 'exploit'")
	}
}

func TestRegistry_All_Empty(t *testing.T) {
	reg := skills.NewRegistry()
	all := reg.All()
	if len(all) != 0 {
		t.Errorf("All() on empty registry: got %d, want 0", len(all))
	}
}

// --- Expand with unknown slash command テスト ---

func TestRegistry_Expand_UnknownSlashCommand(t *testing.T) {
	reg := skills.NewRegistry()
	input := "/unknown-cmd"
	got := reg.Expand(input)
	if got != input {
		t.Errorf("Expand(%q) should return original string for unknown slash command: got %q", input, got)
	}
}

func TestRegistry_Expand_UnknownSlashCommandWithArgs(t *testing.T) {
	reg := skills.NewRegistry()
	input := "/unknown-cmd arg1 arg2"
	got := reg.Expand(input)
	if got != input {
		t.Errorf("Expand(%q) should return original string for unknown slash command: got %q", input, got)
	}
}

// --- parseMDSkill edge cases テスト ---

func TestRegistry_LoadDir_MDSkill_NoFrontmatter(t *testing.T) {
	dir := t.TempDir()

	// --- プレフィックスなしの MD ファイル → スキップされるべき
	md := "This is just plain markdown without frontmatter."
	if err := os.WriteFile(filepath.Join(dir, "plain.md"), []byte(md), 0o600); err != nil {
		t.Fatal(err)
	}

	reg := skills.NewRegistry()
	_ = reg.LoadDir(dir)

	all := reg.All()
	if len(all) != 0 {
		t.Errorf("expected 0 skills for MD without frontmatter, got %d", len(all))
	}
}

func TestRegistry_LoadDir_MDSkill_InvalidFrontmatter(t *testing.T) {
	dir := t.TempDir()

	// 不正な YAML frontmatter
	md := "---\n:::invalid:::yaml\n---\n\nSome prompt."
	if err := os.WriteFile(filepath.Join(dir, "invalid.md"), []byte(md), 0o600); err != nil {
		t.Fatal(err)
	}

	reg := skills.NewRegistry()
	_ = reg.LoadDir(dir)

	all := reg.All()
	if len(all) != 0 {
		t.Errorf("expected 0 skills for invalid frontmatter, got %d", len(all))
	}
}

func TestRegistry_LoadDir_MDSkill_EmptyName(t *testing.T) {
	dir := t.TempDir()

	// frontmatter に name がない（空文字列）→ スキップ
	md := "---\nname: \"\"\ndescription: \"No name\"\n---\n\nSome prompt."
	if err := os.WriteFile(filepath.Join(dir, "emptyname.md"), []byte(md), 0o600); err != nil {
		t.Fatal(err)
	}

	reg := skills.NewRegistry()
	_ = reg.LoadDir(dir)

	all := reg.All()
	if len(all) != 0 {
		t.Errorf("expected 0 skills for empty-name MD, got %d", len(all))
	}
}

func TestRegistry_LoadDir_MDSkill_IncompleteFrontmatter(t *testing.T) {
	dir := t.TempDir()

	// --- で始まるが閉じ --- がない → parts < 3 でスキップ
	md := "---\nname: broken\ndescription: \"Broken\"\n"
	if err := os.WriteFile(filepath.Join(dir, "incomplete.md"), []byte(md), 0o600); err != nil {
		t.Fatal(err)
	}

	reg := skills.NewRegistry()
	_ = reg.LoadDir(dir)

	all := reg.All()
	if len(all) != 0 {
		t.Errorf("expected 0 skills for incomplete frontmatter, got %d", len(all))
	}
}
