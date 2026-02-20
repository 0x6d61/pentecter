// Package memory は Brain の発見物（脆弱性・認証情報・アーティファクト）を
// ホストごとのディレクトリに型別ファイルとして永続化する。
//
// ディレクトリ構造:
//
//	memory/<host>/vulnerability.txt
//	memory/<host>/credential.txt
//	memory/<host>/artifact.txt
//	memory/<host>/finding.txt
package memory

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/0x6d61/pentecter/pkg/schema"
)

// 型別ファイル名の定義
const (
	fileVulnerability = "vulnerability.txt"
	fileCredential    = "credential.txt"
	fileArtifact      = "artifact.txt"
	fileFinding       = "finding.txt"
)

// sectionOrder は Read 時のセクション出力順序を定義する。
var sectionOrder = []struct {
	header   string
	filename string
}{
	{"## Vulnerabilities", fileVulnerability},
	{"## Credentials", fileCredential},
	{"## Artifacts", fileArtifact},
	{"## Findings", fileFinding},
}

// Store はメモリファイルの読み書きを管理する。
type Store struct {
	dir string // メモリファイルを保存するベースディレクトリ
}

// NewStore は指定ディレクトリを使う Store を返す。
// ディレクトリが存在しない場合は Record 時に自動作成する。
func NewStore(dir string) *Store {
	return &Store{dir: dir}
}

// BaseDir はメモリストアのベースディレクトリを返す。
func (s *Store) BaseDir() string {
	return s.dir
}

// Record は発見物を host に対応する型別ファイルに追記する。
// ホストディレクトリが存在しない場合は自動作成する。
func (s *Store) Record(host string, m *schema.Memory) error {
	hostDir := filepath.Join(s.dir, sanitizeFilename(host))
	if err := os.MkdirAll(hostDir, 0o750); err != nil {
		return fmt.Errorf("memory: mkdir: %w", err)
	}

	filename := typeToFilename(m.Type)
	path := filepath.Join(hostDir, filename)

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("memory: open file: %w", err)
	}
	defer func() { _ = f.Close() }()

	entry := formatEntry(m)
	if _, err := f.WriteString(entry); err != nil {
		return fmt.Errorf("memory: write entry: %w", err)
	}
	return nil
}

// Read は host のすべての型別ファイルを読み込み、セクションヘッダー付きで結合して返す。
// ホストディレクトリが存在しない場合は空文字列を返す。
// 存在しないファイルや空ファイルのセクションはスキップする。
func (s *Store) Read(host string) string {
	hostDir := filepath.Join(s.dir, sanitizeFilename(host))

	// ホストディレクトリが存在しなければ空文字列
	if _, err := os.Stat(hostDir); os.IsNotExist(err) {
		return ""
	}

	var sb strings.Builder
	for _, sec := range sectionOrder {
		data, err := os.ReadFile(filepath.Join(hostDir, sec.filename))
		if err != nil || len(data) == 0 {
			continue
		}
		if sb.Len() > 0 {
			sb.WriteString("\n")
		}
		sb.WriteString(sec.header)
		sb.WriteString("\n")
		sb.Write(data)
	}
	return sb.String()
}

// typeToFilename は MemoryType を対応するファイル名に変換する。
func typeToFilename(t schema.MemoryType) string {
	switch t {
	case schema.MemoryVulnerability:
		return fileVulnerability
	case schema.MemoryCredential:
		return fileCredential
	case schema.MemoryArtifact:
		return fileArtifact
	default: // MemoryNote → finding.txt
		return fileFinding
	}
}

// formatEntry は Memory をタイムスタンプ付きのテキストエントリに変換する。
func formatEntry(m *schema.Memory) string {
	ts := time.Now().Format("2006-01-02 15:04:05")

	switch m.Type {
	case schema.MemoryVulnerability:
		severity := strings.ToUpper(m.Severity)
		if severity == "" {
			severity = "INFO"
		}
		return fmt.Sprintf("[%s] [%s] %s\n%s\n\n", ts, severity, m.Title, m.Description)

	case schema.MemoryCredential:
		return fmt.Sprintf("[%s] %s\n%s\n\n", ts, m.Title, m.Description)

	case schema.MemoryArtifact:
		return fmt.Sprintf("[%s] %s\n%s\n\n", ts, m.Title, m.Description)

	default: // MemoryNote
		return fmt.Sprintf("[%s] %s\n%s\n\n", ts, m.Title, m.Description)
	}
}

// sanitizeFilename はホスト名をディレクトリ名として安全な形式に変換する。
// IP アドレスとドメイン名はそのまま使用できる。
// セキュリティ: パストラバーサルを防ぐため / と \ を除去する。
func sanitizeFilename(host string) string {
	// パス区切り文字を除去（パストラバーサル防止）
	host = strings.ReplaceAll(host, "/", "_")
	host = strings.ReplaceAll(host, "\\", "_")
	host = strings.ReplaceAll(host, "..", "_")
	if host == "" {
		host = "unknown"
	}
	return host
}
