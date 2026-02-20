package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// SaveRawOutput はコマンドの生出力をファイルに保存する。
// baseDir/<host>/raw/<timestamp>_<tool>.txt に保存し、ファイルパスを返す。
func SaveRawOutput(baseDir, host, command, output string) (string, error) {
	rawDir := filepath.Join(baseDir, host, "raw")
	if err := os.MkdirAll(rawDir, 0o755); err != nil {
		return "", fmt.Errorf("create raw dir: %w", err)
	}

	toolName := extractToolName(command)
	timestamp := time.Now().Format("20060102-150405")
	filename := fmt.Sprintf("%s_%s.txt", timestamp, toolName)
	filePath := filepath.Join(rawDir, filename)

	// ヘッダー付きで保存
	var sb strings.Builder
	sb.WriteString("# Command: ")
	sb.WriteString(command)
	sb.WriteString("\n# Timestamp: ")
	sb.WriteString(time.Now().Format(time.RFC3339))
	sb.WriteString("\n# ---\n")
	sb.WriteString(output)

	if err := os.WriteFile(filePath, []byte(sb.String()), 0o644); err != nil {
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
