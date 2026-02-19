package knowledge_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0x6d61/pentecter/internal/knowledge"
)

// --- テスト用ヘルパー ---

// setupTestData はテスト用のマークダウンディレクトリ構造を作成する。
// HackTricks の構造を模倣する。
func setupTestData(t *testing.T) string {
	t.Helper()
	base := t.TempDir()

	// pentesting-web/sql-injection/README.md
	sqlDir := filepath.Join(base, "pentesting-web", "sql-injection")
	if err := os.MkdirAll(sqlDir, 0o755); err != nil {
		t.Fatal(err)
	}
	sqlContent := `# SQL Injection

## Basic SQL Injection

The most common SQL injection technique.

SELECT * FROM users WHERE id='1' OR '1'='1'

## Union Based

UNION SELECT 1,2,3 FROM information_schema.tables

## Blind SQL Injection

Use time-based or boolean-based blind injection.
`
	if err := os.WriteFile(filepath.Join(sqlDir, "README.md"), []byte(sqlContent), 0o644); err != nil {
		t.Fatal(err)
	}

	// pentesting-web/xss.md
	webDir := filepath.Join(base, "pentesting-web")
	xssContent := `# XSS Cross Site Scripting

## Reflected XSS

<script>alert(1)</script>

Reflected XSS occurs when user input is reflected in the response.

## Stored XSS

Stored XSS persists in the database and is served to other users.

## DOM Based XSS

DOM-based XSS manipulates the DOM directly.
`
	if err := os.WriteFile(filepath.Join(webDir, "xss.md"), []byte(xssContent), 0o644); err != nil {
		t.Fatal(err)
	}

	// network-services-pentesting/ftp.md
	netDir := filepath.Join(base, "network-services-pentesting")
	if err := os.MkdirAll(netDir, 0o755); err != nil {
		t.Fatal(err)
	}
	ftpContent := `# FTP Pentesting

## Anonymous Login

ftp anonymous@target

Check if anonymous login is allowed.

## vsftpd 2.3.4 Backdoor

The vsftpd 2.3.4 backdoor allows remote code execution.

## FTP Bounce Attack

Use PORT command to scan internal networks.
`
	if err := os.WriteFile(filepath.Join(netDir, "ftp.md"), []byte(ftpContent), 0o644); err != nil {
		t.Fatal(err)
	}

	return base
}

// --- NewStore テスト ---

func TestNewStore_ValidPath(t *testing.T) {
	base := setupTestData(t)
	store := knowledge.NewStore(base)
	if store == nil {
		t.Fatal("NewStore with valid path should return non-nil Store")
	}
}

func TestNewStore_EmptyPath(t *testing.T) {
	store := knowledge.NewStore("")
	if store != nil {
		t.Fatal("NewStore with empty path should return nil")
	}
}

func TestNewStore_NonExistentPath(t *testing.T) {
	store := knowledge.NewStore("/nonexistent/path/that/does/not/exist")
	if store != nil {
		t.Fatal("NewStore with non-existent path should return nil")
	}
}

// --- Search テスト ---

func TestSearch_SingleKeyword(t *testing.T) {
	base := setupTestData(t)
	store := knowledge.NewStore(base)

	results := store.Search("sql", 10)
	if len(results) == 0 {
		t.Fatal("Search for 'sql' should return results")
	}

	// sql-injection/README.md が結果に含まれること
	found := false
	for _, r := range results {
		if strings.Contains(r.File, "sql-injection") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected sql-injection file in results, got: %v", results)
	}
}

func TestSearch_MultipleKeywords(t *testing.T) {
	base := setupTestData(t)
	store := knowledge.NewStore(base)

	results := store.Search("union select", 10)
	if len(results) == 0 {
		t.Fatal("Search for 'union select' should return results")
	}

	// SQL Injection ファイルがマッチすること
	found := false
	for _, r := range results {
		if strings.Contains(r.File, "sql-injection") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected sql-injection file in results for 'union select', got: %v", results)
	}
}

func TestSearch_CaseInsensitive(t *testing.T) {
	base := setupTestData(t)
	store := knowledge.NewStore(base)

	// 大文字で検索しても小文字のコンテンツにマッチすること
	results := store.Search("XSS", 10)
	if len(results) == 0 {
		t.Fatal("Search for 'XSS' should return results (case-insensitive)")
	}

	found := false
	for _, r := range results {
		if strings.Contains(r.File, "xss") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected xss file in results for 'XSS' search, got: %v", results)
	}
}

func TestSearch_MaxResults(t *testing.T) {
	base := setupTestData(t)
	store := knowledge.NewStore(base)

	// maxResults=1 で結果を制限
	results := store.Search("the", 1)
	if len(results) > 1 {
		t.Errorf("Search with maxResults=1 should return at most 1 result, got %d", len(results))
	}
}

func TestSearch_NoResults(t *testing.T) {
	base := setupTestData(t)
	store := knowledge.NewStore(base)

	results := store.Search("zzzznonexistentzzzzz", 10)
	if len(results) != 0 {
		t.Errorf("Search for nonexistent term should return empty slice, got %d results", len(results))
	}
}

func TestSearch_ResultFields(t *testing.T) {
	base := setupTestData(t)
	store := knowledge.NewStore(base)

	results := store.Search("anonymous", 10)
	if len(results) == 0 {
		t.Fatal("Search for 'anonymous' should return results")
	}

	r := results[0]
	// File は相対パスであること
	if filepath.IsAbs(r.File) {
		t.Errorf("File should be relative path, got: %s", r.File)
	}
	// Title は H1 ヘッダーであること
	if r.Title == "" {
		t.Error("Title should not be empty")
	}
	// Section は H2/H3 ヘッダーであること
	if r.Section == "" {
		t.Error("Section should not be empty")
	}
	// Snippet はマッチ行のコンテキストであること
	if r.Snippet == "" {
		t.Error("Snippet should not be empty")
	}
	// MatchCount は 0 より大きいこと
	if r.MatchCount <= 0 {
		t.Errorf("MatchCount should be > 0, got %d", r.MatchCount)
	}
}

func TestSearch_SortedByMatchCount(t *testing.T) {
	base := setupTestData(t)
	store := knowledge.NewStore(base)

	// "the" は複数ファイルに出現するキーワード
	results := store.Search("the", 10)
	if len(results) < 2 {
		t.Skipf("Need at least 2 results to test sorting, got %d", len(results))
	}

	// 結果がマッチ数の降順でソートされていること
	for i := 1; i < len(results); i++ {
		if results[i].MatchCount > results[i-1].MatchCount {
			t.Errorf("Results should be sorted by MatchCount descending: result[%d].MatchCount=%d > result[%d].MatchCount=%d",
				i, results[i].MatchCount, i-1, results[i-1].MatchCount)
		}
	}
}

func TestSearch_EmptyQuery(t *testing.T) {
	base := setupTestData(t)
	store := knowledge.NewStore(base)

	results := store.Search("", 10)
	if len(results) != 0 {
		t.Errorf("Search with empty query should return empty slice, got %d results", len(results))
	}
}

// --- ReadFile テスト ---

func TestReadFile_Valid(t *testing.T) {
	base := setupTestData(t)
	store := knowledge.NewStore(base)

	content, err := store.ReadFile("pentesting-web/sql-injection/README.md", 64*1024)
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	if content == "" {
		t.Fatal("ReadFile should return non-empty content")
	}
	if !strings.Contains(content, "SQL Injection") {
		t.Errorf("ReadFile content should contain 'SQL Injection', got: %s", content)
	}
}

func TestReadFile_MaxBytes(t *testing.T) {
	base := setupTestData(t)
	store := knowledge.NewStore(base)

	// maxBytes=20 で切り詰め
	content, err := store.ReadFile("pentesting-web/sql-injection/README.md", 20)
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	if len(content) > 20 {
		t.Errorf("ReadFile with maxBytes=20 should return at most 20 bytes, got %d", len(content))
	}
}

func TestReadFile_NotFound(t *testing.T) {
	base := setupTestData(t)
	store := knowledge.NewStore(base)

	_, err := store.ReadFile("nonexistent/file.md", 64*1024)
	if err == nil {
		t.Fatal("ReadFile for nonexistent file should return error")
	}
}

func TestReadFile_PathTraversal(t *testing.T) {
	base := setupTestData(t)
	store := knowledge.NewStore(base)

	// パストラバーサル攻撃を拒否すること
	_, err := store.ReadFile("../../../etc/passwd", 64*1024)
	if err == nil {
		t.Fatal("ReadFile should reject path traversal")
	}
}

func TestReadFile_PathTraversal_EncodedDots(t *testing.T) {
	base := setupTestData(t)
	store := knowledge.NewStore(base)

	// basePath の外に出るパスを拒否すること
	_, err := store.ReadFile("pentesting-web/../../etc/passwd", 64*1024)
	if err == nil {
		t.Fatal("ReadFile should reject path traversal with encoded dots")
	}
}

// --- ListCategories テスト ---

func TestListCategories(t *testing.T) {
	base := setupTestData(t)
	store := knowledge.NewStore(base)

	categories := store.ListCategories()
	if len(categories) == 0 {
		t.Fatal("ListCategories should return non-empty result")
	}

	// トップレベルのカテゴリ名を確認
	names := make(map[string]bool)
	for _, c := range categories {
		names[c.Name] = true
	}

	if !names["pentesting-web"] {
		t.Error("Expected 'pentesting-web' category")
	}
	if !names["network-services-pentesting"] {
		t.Error("Expected 'network-services-pentesting' category")
	}
}

func TestListCategories_FileCount(t *testing.T) {
	base := setupTestData(t)
	store := knowledge.NewStore(base)

	categories := store.ListCategories()

	for _, c := range categories {
		if c.Name == "pentesting-web" {
			// pentesting-web には xss.md と sql-injection/README.md の 2 ファイル
			if c.FileCount != 2 {
				t.Errorf("Expected FileCount=2 for pentesting-web, got %d", c.FileCount)
			}
		}
		if c.Name == "network-services-pentesting" {
			// network-services-pentesting には ftp.md の 1 ファイル
			if c.FileCount != 1 {
				t.Errorf("Expected FileCount=1 for network-services-pentesting, got %d", c.FileCount)
			}
		}
	}
}

func TestListCategories_Path(t *testing.T) {
	base := setupTestData(t)
	store := knowledge.NewStore(base)

	categories := store.ListCategories()
	for _, c := range categories {
		// Path はディレクトリ名と一致すること
		if c.Path != c.Name {
			t.Errorf("Expected Path=%q to equal Name=%q for top-level category", c.Path, c.Name)
		}
	}
}
