package agent

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// RawOutputEntry は構造化された raw output の1エントリ
type RawOutputEntry struct {
	ID        string `json:"id"`        // UUID
	Command   string `json:"command"`   // 実行コマンド
	Output    string `json:"output"`    // コマンド出力
	Timestamp string `json:"timestamp"` // RFC3339
	Tool      string `json:"tool"`      // extractToolName の結果
	ExitCode  int    `json:"exit_code"` // コマンドの exit code
}

// generateUUID は crypto/rand を使って UUID v4 を生成する。
func generateUUID() string {
	var buf [16]byte
	_, _ = rand.Read(buf[:])
	buf[6] = (buf[6] & 0x0f) | 0x40 // version 4
	buf[8] = (buf[8] & 0x3f) | 0x80 // variant
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		buf[0:4], buf[4:6], buf[6:8], buf[8:10], buf[10:16])
}

// SaveRawOutput はコマンドの生出力を JSON ファイルに保存する。
// baseDir/<host>/raw/<timestamp>_<tool>.json に保存し、ファイルパスを返す。
func SaveRawOutput(baseDir, host, command, output string, exitCode int) (string, error) {
	rawDir := filepath.Join(baseDir, host, "raw")
	if err := os.MkdirAll(rawDir, 0o755); err != nil {
		return "", fmt.Errorf("create raw dir: %w", err)
	}

	toolName := extractToolName(command)
	timestamp := time.Now().Format("20060102-150405")
	filename := fmt.Sprintf("%s_%s.json", timestamp, toolName)
	filePath := filepath.Join(rawDir, filename)

	entry := RawOutputEntry{
		ID:        generateUUID(),
		Command:   command,
		Output:    output,
		Timestamp: time.Now().Format(time.RFC3339),
		Tool:      toolName,
		ExitCode:  exitCode,
	}

	data, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal raw output: %w", err)
	}

	if err := os.WriteFile(filePath, data, 0o600); err != nil {
		return "", fmt.Errorf("write raw output: %w", err)
	}

	return filePath, nil
}

// extractToolName はコマンド文字列からツール名を抽出する。
// "sudo nmap -sV" -> "nmap", "/usr/bin/ffuf -w ..." -> "ffuf"
func extractToolName(command string) string {
	if command == "" {
		return "unknown"
	}
	parts := strings.Fields(command)
	if len(parts) == 0 {
		return "unknown"
	}

	bin := parts[0]
	// sudo を飛ばす
	if bin == "sudo" && len(parts) > 1 {
		bin = parts[1]
	}
	// パスからベース名を取得
	bin = filepath.Base(bin)
	// ./ プレフィックスを除去
	bin = strings.TrimPrefix(bin, "./")

	if bin == "" {
		return "unknown"
	}
	return bin
}
