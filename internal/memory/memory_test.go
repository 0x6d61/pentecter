package memory_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0x6d61/pentecter/internal/memory"
	"github.com/0x6d61/pentecter/pkg/schema"
)

func TestStore_Record_CreatesFile(t *testing.T) {
	dir := t.TempDir()
	s := memory.NewStore(dir)

	err := s.Record("10.0.0.5", &schema.Memory{
		Type:        schema.MemoryVulnerability,
		Title:       "CVE-2021-41773",
		Description: "Apache 2.4.49 Path Traversal confirmed",
		Severity:    "critical",
	})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}

	path := filepath.Join(dir, "10.0.0.5.md")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("File not created: %v", err)
	}

	content := string(data)
	if !strings.Contains(content, "CVE-2021-41773") {
		t.Errorf("File should contain CVE title, got:\n%s", content)
	}
	if !strings.Contains(strings.ToLower(content), "critical") {
		t.Errorf("File should contain severity, got:\n%s", content)
	}
}

func TestStore_Record_Appends(t *testing.T) {
	dir := t.TempDir()
	s := memory.NewStore(dir)

	_ = s.Record("10.0.0.5", &schema.Memory{
		Type:  schema.MemoryVulnerability,
		Title: "CVE-2021-41773",
	})
	_ = s.Record("10.0.0.5", &schema.Memory{
		Type:  schema.MemoryCredential,
		Title: "MySQL: root / empty password",
	})

	data, _ := os.ReadFile(filepath.Join(dir, "10.0.0.5.md"))
	content := string(data)

	if !strings.Contains(content, "CVE-2021-41773") {
		t.Error("First entry missing")
	}
	if !strings.Contains(content, "MySQL") {
		t.Error("Second entry missing")
	}
}

func TestStore_Record_DomainHost(t *testing.T) {
	dir := t.TempDir()
	s := memory.NewStore(dir)

	err := s.Record("example.com", &schema.Memory{
		Type:  schema.MemoryNote,
		Title: "Domain target",
	})
	if err != nil {
		t.Fatalf("Domain host record: %v", err)
	}

	// ファイル名の . はそのまま（ホスト名として有効）
	_, err = os.ReadFile(filepath.Join(dir, "example.com.md"))
	if err != nil {
		t.Fatalf("File not found for domain host: %v", err)
	}
}
