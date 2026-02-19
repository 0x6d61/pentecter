package memory_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0x6d61/pentecter/internal/memory"
	"github.com/0x6d61/pentecter/pkg/schema"
)

// --- Record: 型別ファイル振り分けテスト ---

func TestStore_Record_WritesToCorrectFile(t *testing.T) {
	dir := t.TempDir()
	s := memory.NewStore(dir)

	tests := []struct {
		name     string
		mem      *schema.Memory
		wantFile string // host dir 内の期待されるファイル名
	}{
		{
			name: "vulnerability goes to vulnerability.txt",
			mem: &schema.Memory{
				Type:        schema.MemoryVulnerability,
				Title:       "CVE-2021-41773 Apache Path Traversal",
				Description: "Apache 2.4.49 vulnerable to path traversal allowing remote code execution.",
				Severity:    "critical",
			},
			wantFile: "vulnerability.txt",
		},
		{
			name: "credential goes to credential.txt",
			mem: &schema.Memory{
				Type:        schema.MemoryCredential,
				Title:       "FTP Admin Credentials",
				Description: "user:password found in vsftpd banner",
			},
			wantFile: "credential.txt",
		},
		{
			name: "artifact goes to artifact.txt",
			mem: &schema.Memory{
				Type:        schema.MemoryArtifact,
				Title:       "etc/passwd",
				Description: "Downloaded /etc/passwd via path traversal",
			},
			wantFile: "artifact.txt",
		},
		{
			name: "note goes to finding.txt",
			mem: &schema.Memory{
				Type:        schema.MemoryNote,
				Title:       "Initial assessment",
				Description: "Target appears to be a web server",
			},
			wantFile: "finding.txt",
		},
	}

	host := "10.0.0.5"
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := s.Record(host, tt.mem)
			if err != nil {
				t.Fatalf("Record: %v", err)
			}

			path := filepath.Join(dir, host, tt.wantFile)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("Expected file %s to exist: %v", tt.wantFile, err)
			}

			content := string(data)
			if !strings.Contains(content, tt.mem.Title) {
				t.Errorf("File %s should contain title %q, got:\n%s", tt.wantFile, tt.mem.Title, content)
			}
			if !strings.Contains(content, tt.mem.Description) {
				t.Errorf("File %s should contain description %q, got:\n%s", tt.wantFile, tt.mem.Description, content)
			}
		})
	}
}

func TestStore_Record_VulnerabilityFormat(t *testing.T) {
	dir := t.TempDir()
	s := memory.NewStore(dir)

	err := s.Record("10.0.0.5", &schema.Memory{
		Type:        schema.MemoryVulnerability,
		Title:       "CVE-2021-41773 Apache Path Traversal",
		Description: "Apache 2.4.49 vulnerable to path traversal.",
		Severity:    "critical",
	})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}

	data, _ := os.ReadFile(filepath.Join(dir, "10.0.0.5", "vulnerability.txt"))
	content := string(data)

	// タイムスタンプ形式: [YYYY-MM-DD HH:MM:SS]
	if !strings.Contains(content, "[CRITICAL]") {
		t.Errorf("Expected [CRITICAL] severity tag, got:\n%s", content)
	}
	if !strings.Contains(content, "CVE-2021-41773 Apache Path Traversal") {
		t.Errorf("Expected title in entry, got:\n%s", content)
	}
}

func TestStore_Record_VulnerabilityDefaultSeverity(t *testing.T) {
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

	data, _ := os.ReadFile(filepath.Join(dir, "10.0.0.40", "vulnerability.txt"))
	content := string(data)
	if !strings.Contains(content, "[INFO]") {
		t.Errorf("Expected '[INFO]' for empty severity, got:\n%s", content)
	}
}

func TestStore_Record_CreatesHostDirectory(t *testing.T) {
	dir := t.TempDir()
	s := memory.NewStore(dir)

	host := "192.168.1.100"
	err := s.Record(host, &schema.Memory{
		Type:        schema.MemoryVulnerability,
		Title:       "Test Vuln",
		Description: "Test description",
		Severity:    "high",
	})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}

	// ホストディレクトリが自動作成されることを確認
	hostDir := filepath.Join(dir, host)
	info, err := os.Stat(hostDir)
	if err != nil {
		t.Fatalf("Host directory should be created: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("Expected %s to be a directory", hostDir)
	}
}

func TestStore_Record_AppendsToSameFile(t *testing.T) {
	dir := t.TempDir()
	s := memory.NewStore(dir)

	host := "10.0.0.5"
	_ = s.Record(host, &schema.Memory{
		Type:        schema.MemoryVulnerability,
		Title:       "CVE-2021-41773",
		Description: "First vuln",
		Severity:    "critical",
	})
	_ = s.Record(host, &schema.Memory{
		Type:        schema.MemoryVulnerability,
		Title:       "CVE-2022-12345",
		Description: "Second vuln",
		Severity:    "high",
	})

	data, _ := os.ReadFile(filepath.Join(dir, host, "vulnerability.txt"))
	content := string(data)

	if !strings.Contains(content, "CVE-2021-41773") {
		t.Error("First entry missing from vulnerability.txt")
	}
	if !strings.Contains(content, "CVE-2022-12345") {
		t.Error("Second entry missing from vulnerability.txt")
	}
}

// --- Read テスト ---

func TestStore_Read_CombinesSections(t *testing.T) {
	dir := t.TempDir()
	s := memory.NewStore(dir)

	host := "192.168.1.1"

	// 各タイプのエントリを記録
	_ = s.Record(host, &schema.Memory{
		Type:        schema.MemoryVulnerability,
		Title:       "Open SSH",
		Description: "SSH port 22 is open with weak config",
		Severity:    "high",
	})
	_ = s.Record(host, &schema.Memory{
		Type:        schema.MemoryCredential,
		Title:       "MySQL root",
		Description: "root:password123",
	})
	_ = s.Record(host, &schema.Memory{
		Type:        schema.MemoryArtifact,
		Title:       "etc/passwd",
		Description: "Downloaded /etc/passwd",
	})
	_ = s.Record(host, &schema.Memory{
		Type:        schema.MemoryNote,
		Title:       "Initial scan",
		Description: "Host appears to be Linux",
	})

	content := s.Read(host)
	if content == "" {
		t.Fatal("Read returned empty string after Record")
	}

	// セクションヘッダーが正しい順序で含まれること
	if !strings.Contains(content, "## Vulnerabilities") {
		t.Errorf("Expected '## Vulnerabilities' section header, got:\n%s", content)
	}
	if !strings.Contains(content, "## Credentials") {
		t.Errorf("Expected '## Credentials' section header, got:\n%s", content)
	}
	if !strings.Contains(content, "## Artifacts") {
		t.Errorf("Expected '## Artifacts' section header, got:\n%s", content)
	}
	if !strings.Contains(content, "## Findings") {
		t.Errorf("Expected '## Findings' section header, got:\n%s", content)
	}

	// 各エントリの内容が含まれること
	if !strings.Contains(content, "Open SSH") {
		t.Errorf("Expected vulnerability title, got:\n%s", content)
	}
	if !strings.Contains(content, "MySQL root") {
		t.Errorf("Expected credential title, got:\n%s", content)
	}
	if !strings.Contains(content, "etc/passwd") {
		t.Errorf("Expected artifact title, got:\n%s", content)
	}
	if !strings.Contains(content, "Initial scan") {
		t.Errorf("Expected finding title, got:\n%s", content)
	}
}

func TestStore_Read_SkipsEmptyFiles(t *testing.T) {
	dir := t.TempDir()
	s := memory.NewStore(dir)

	host := "10.0.0.99"

	// vulnerability だけ記録
	_ = s.Record(host, &schema.Memory{
		Type:        schema.MemoryVulnerability,
		Title:       "Only Vuln",
		Description: "The only entry",
		Severity:    "low",
	})

	content := s.Read(host)

	// Vulnerabilities セクションだけ含まれる
	if !strings.Contains(content, "## Vulnerabilities") {
		t.Errorf("Expected '## Vulnerabilities', got:\n%s", content)
	}

	// 他のセクションは含まれない（ファイルが存在しないため）
	if strings.Contains(content, "## Credentials") {
		t.Errorf("Should not contain '## Credentials' when no credential file exists, got:\n%s", content)
	}
	if strings.Contains(content, "## Artifacts") {
		t.Errorf("Should not contain '## Artifacts' when no artifact file exists, got:\n%s", content)
	}
	if strings.Contains(content, "## Findings") {
		t.Errorf("Should not contain '## Findings' when no finding file exists, got:\n%s", content)
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

func TestStore_Record_DomainHost(t *testing.T) {
	dir := t.TempDir()
	s := memory.NewStore(dir)

	err := s.Record("example.com", &schema.Memory{
		Type:        schema.MemoryNote,
		Title:       "Domain target",
		Description: "Testing domain host",
	})
	if err != nil {
		t.Fatalf("Domain host record: %v", err)
	}

	// ドメインホスト名のディレクトリが作成されること
	hostDir := filepath.Join(dir, "example.com")
	info, err := os.Stat(hostDir)
	if err != nil {
		t.Fatalf("Host directory not found for domain host: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("Expected directory for domain host")
	}

	// finding.txt が存在すること
	data, err := os.ReadFile(filepath.Join(hostDir, "finding.txt"))
	if err != nil {
		t.Fatalf("finding.txt not found: %v", err)
	}
	if !strings.Contains(string(data), "Domain target") {
		t.Errorf("finding.txt should contain the title")
	}
}

// --- sanitizeFilename テスト ---

func TestStore_SanitizeFilename_PathTraversal(t *testing.T) {
	dir := t.TempDir()
	s := memory.NewStore(dir)

	// パストラバーサル攻撃を含むホスト名
	err := s.Record("../../etc/passwd", &schema.Memory{
		Type:        schema.MemoryNote,
		Title:       "Traversal test",
		Description: "Should be sanitized",
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
		t.Fatalf("expected 1 directory in dir, got %d", len(entries))
	}

	// サニタイズされたディレクトリ名であること
	dname := entries[0].Name()
	if strings.Contains(dname, "..") {
		t.Errorf("directory name should not contain '..': got %q", dname)
	}
	if strings.Contains(dname, "/") || strings.Contains(dname, "\\") {
		t.Errorf("directory name should not contain path separators: got %q", dname)
	}
	if !entries[0].IsDir() {
		t.Errorf("expected a directory, got a file: %q", dname)
	}
}

func TestStore_SanitizeFilename_Backslashes(t *testing.T) {
	dir := t.TempDir()
	s := memory.NewStore(dir)

	err := s.Record(`host\with\backslashes`, &schema.Memory{
		Type:        schema.MemoryNote,
		Title:       "Backslash test",
		Description: "Should be sanitized",
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
		Type:        schema.MemoryNote,
		Title:       "Empty host test",
		Description: "Should go to unknown dir",
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

	// unknown ディレクトリが存在することを確認
	unknownDir := filepath.Join(dir, "unknown")
	info, err := os.Stat(unknownDir)
	if err != nil {
		t.Fatalf("unknown directory should exist for empty host: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("Expected unknown to be a directory")
	}
}

func TestStore_Record_TimestampFormat(t *testing.T) {
	dir := t.TempDir()
	s := memory.NewStore(dir)

	err := s.Record("10.0.0.1", &schema.Memory{
		Type:        schema.MemoryCredential,
		Title:       "FTP Admin Credentials",
		Description: "user:password found in vsftpd banner",
	})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}

	data, _ := os.ReadFile(filepath.Join(dir, "10.0.0.1", "credential.txt"))
	content := string(data)

	// タイムスタンプが [YYYY-MM-DD HH:MM:SS] 形式であること
	// 正確な時刻は検証できないので、パターンの存在を確認
	if !strings.Contains(content, "[20") {
		t.Errorf("Expected timestamp starting with [20, got:\n%s", content)
	}
}
