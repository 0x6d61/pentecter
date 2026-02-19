// Package memory は Brain の発見物（脆弱性・認証情報・アーティファクト）を
// ホストごとの Markdown ファイルに永続化する。
package memory

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/0x6d61/pentecter/pkg/schema"
)

// Store はメモリファイルの読み書きを管理する。
type Store struct {
	dir string // メモリファイルを保存するディレクトリ
}

// NewStore は指定ディレクトリを使う Store を返す。
// ディレクトリが存在しない場合は Record 時に自動作成する。
func NewStore(dir string) *Store {
	return &Store{dir: dir}
}

// Record は発見物を host に対応するファイルに追記する。
// ファイルが存在しない場合は新規作成してヘッダーを書く。
func (s *Store) Record(host string, m *schema.Memory) error {
	if err := os.MkdirAll(s.dir, 0o750); err != nil {
		return fmt.Errorf("memory: mkdir: %w", err)
	}

	// ファイル名: memory/<host>.md（ホスト名の特殊文字はそのまま）
	filename := sanitizeFilename(host) + ".md"
	path := filepath.Join(s.dir, filename)

	// ファイルが存在しなければヘッダーを書く
	isNew := false
	if _, err := os.Stat(path); os.IsNotExist(err) {
		isNew = true
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("memory: open file: %w", err)
	}
	defer func() { _ = f.Close() }()

	if isNew {
		header := fmt.Sprintf("# Pentecter Memory: %s\n\nGenerated: %s\n\n", host, time.Now().Format("2006-01-02 15:04:05"))
		if _, err := f.WriteString(header); err != nil {
			return fmt.Errorf("memory: write header: %w", err)
		}
	}

	entry := formatEntry(m)
	if _, err := f.WriteString(entry); err != nil {
		return fmt.Errorf("memory: write entry: %w", err)
	}
	return nil
}

// Read は host のメモリファイル全文を返す。ファイルが存在しない場合は空文字列。
func (s *Store) Read(host string) string {
	filename := sanitizeFilename(host) + ".md"
	data, err := os.ReadFile(filepath.Join(s.dir, filename))
	if err != nil {
		return ""
	}
	return string(data)
}

// formatEntry は Memory を Markdown エントリに変換する。
func formatEntry(m *schema.Memory) string {
	ts := time.Now().Format("15:04:05")

	switch m.Type {
	case schema.MemoryVulnerability:
		severity := strings.ToUpper(m.Severity)
		if severity == "" {
			severity = "INFO"
		}
		return fmt.Sprintf("## [%s] %s\n- **Time**: %s\n- **Description**: %s\n\n",
			severity, m.Title, ts, m.Description)

	case schema.MemoryCredential:
		return fmt.Sprintf("## Credential: %s\n- **Time**: %s\n- **Details**: %s\n\n",
			m.Title, ts, m.Description)

	case schema.MemoryArtifact:
		return fmt.Sprintf("## Artifact: %s\n- **Time**: %s\n- **Details**: %s\n\n",
			m.Title, ts, m.Description)

	default: // MemoryNote
		return fmt.Sprintf("## Note: %s\n- **Time**: %s\n- **Content**: %s\n\n",
			m.Title, ts, m.Description)
	}
}

// sanitizeFilename はホスト名をファイル名として安全な形式に変換する。
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
