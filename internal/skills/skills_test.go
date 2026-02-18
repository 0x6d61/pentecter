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
