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

// --- Read テスト ---

func TestStore_Read_RecordedContent(t *testing.T) {
	dir := t.TempDir()
	s := memory.NewStore(dir)

	// 記録してから Read で読み返す
	err := s.Record("192.168.1.1", &schema.Memory{
		Type:        schema.MemoryVulnerability,
		Title:       "Open SSH",
		Description: "SSH port 22 is open with weak config",
		Severity:    "high",
	})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}

	content := s.Read("192.168.1.1")
	if content == "" {
		t.Fatal("Read returned empty string after Record")
	}
	if !strings.Contains(content, "Open SSH") {
		t.Errorf("Read content should contain title 'Open SSH', got:\n%s", content)
	}
	if !strings.Contains(content, "SSH port 22 is open with weak config") {
		t.Errorf("Read content should contain description, got:\n%s", content)
	}
	if !strings.Contains(content, "Pentecter Memory: 192.168.1.1") {
		t.Errorf("Read content should contain header, got:\n%s", content)
	}
}

func TestStore_Read_NonexistentHost(t *testing.T) {
	dir := t.TempDir()
	s := memory.NewStore(dir)

	content := s.Read("nonexistent-host")
	if content != "" {
		t.Errorf("Read on nonexistent host should return empty string, got: %q", content)
	}
}

// --- formatEntry テスト（各 MemoryType） ---

func TestStore_FormatEntry_Credential(t *testing.T) {
	dir := t.TempDir()
	s := memory.NewStore(dir)

	err := s.Record("10.0.0.10", &schema.Memory{
		Type:        schema.MemoryCredential,
		Title:       "MySQL root",
		Description: "root:password123",
	})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}

	content := s.Read("10.0.0.10")
	if !strings.Contains(content, "Credential: MySQL root") {
		t.Errorf("Expected 'Credential: MySQL root' in content, got:\n%s", content)
	}
	if !strings.Contains(content, "root:password123") {
		t.Errorf("Expected credential details in content, got:\n%s", content)
	}
}

func TestStore_FormatEntry_Artifact(t *testing.T) {
	dir := t.TempDir()
	s := memory.NewStore(dir)

	err := s.Record("10.0.0.20", &schema.Memory{
		Type:        schema.MemoryArtifact,
		Title:       "etc/passwd",
		Description: "Downloaded /etc/passwd via path traversal",
	})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}

	content := s.Read("10.0.0.20")
	if !strings.Contains(content, "Artifact: etc/passwd") {
		t.Errorf("Expected 'Artifact: etc/passwd' in content, got:\n%s", content)
	}
	if !strings.Contains(content, "Downloaded /etc/passwd via path traversal") {
		t.Errorf("Expected artifact details in content, got:\n%s", content)
	}
}

func TestStore_FormatEntry_Note(t *testing.T) {
	dir := t.TempDir()
	s := memory.NewStore(dir)

	err := s.Record("10.0.0.30", &schema.Memory{
		Type:        schema.MemoryNote,
		Title:       "Initial assessment",
		Description: "Target appears to be a web server",
	})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}

	content := s.Read("10.0.0.30")
	if !strings.Contains(content, "Note: Initial assessment") {
		t.Errorf("Expected 'Note: Initial assessment' in content, got:\n%s", content)
	}
	if !strings.Contains(content, "Target appears to be a web server") {
		t.Errorf("Expected note content in content, got:\n%s", content)
	}
}

func TestStore_FormatEntry_VulnerabilityDefaultSeverity(t *testing.T) {
	dir := t.TempDir()
	s := memory.NewStore(dir)

	// Severity 空 → INFO にフォールバック
	err := s.Record("10.0.0.40", &schema.Memory{
		Type:        schema.MemoryVulnerability,
		Title:       "Generic Vuln",
		Description: "Some vulnerability",
		Severity:    "",
	})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}

	content := s.Read("10.0.0.40")
	if !strings.Contains(content, "[INFO]") {
		t.Errorf("Expected '[INFO]' for empty severity, got:\n%s", content)
	}
}

// --- sanitizeFilename テスト ---

func TestStore_SanitizeFilename_PathTraversal(t *testing.T) {
	dir := t.TempDir()
	s := memory.NewStore(dir)

	// パストラバーサル攻撃を含むホスト名
	err := s.Record("../../etc/passwd", &schema.Memory{
		Type:  schema.MemoryNote,
		Title: "Traversal test",
	})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}

	// ファイルはメモリディレクトリ内に作成されるべき（外部に書き込まれない）
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 file in dir, got %d", len(entries))
	}

	// サニタイズされたファイル名であること
	fname := entries[0].Name()
	if strings.Contains(fname, "..") {
		t.Errorf("filename should not contain '..': got %q", fname)
	}
	if strings.Contains(fname, "/") || strings.Contains(fname, "\\") {
		t.Errorf("filename should not contain path separators: got %q", fname)
	}
}

func TestStore_SanitizeFilename_Backslashes(t *testing.T) {
	dir := t.TempDir()
	s := memory.NewStore(dir)

	err := s.Record(`host\with\backslashes`, &schema.Memory{
		Type:  schema.MemoryNote,
		Title: "Backslash test",
	})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}

	// バックスラッシュは _ に置換されるべき
	content := s.Read(`host\with\backslashes`)
	if content == "" {
		t.Error("Read should find file for host with backslashes")
	}
}

func TestStore_SanitizeFilename_EmptyHost(t *testing.T) {
	dir := t.TempDir()
	s := memory.NewStore(dir)

	err := s.Record("", &schema.Memory{
		Type:  schema.MemoryNote,
		Title: "Empty host test",
	})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}

	// 空ホスト名は "unknown" にフォールバック
	content := s.Read("")
	if content == "" {
		t.Error("Read should find file for empty host (mapped to 'unknown')")
	}
	if !strings.Contains(content, "Empty host test") {
		t.Errorf("File should contain the recorded entry, got:\n%s", content)
	}

	// unknown.md が存在することを確認
	_, err = os.ReadFile(filepath.Join(dir, "unknown.md"))
	if err != nil {
		t.Fatalf("unknown.md should exist for empty host: %v", err)
	}
}
