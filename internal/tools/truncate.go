package tools

import (
	"fmt"
	"strings"
)

// TruncateStrategy はツール出力の切り捨て戦略を表す。
type TruncateStrategy string

const (
	// StrategyHeadTail は先頭N行＋末尾M行を残し中間を省略する。
	// nmap, nikto などの汎用ツール向け。
	StrategyHeadTail TruncateStrategy = "head_tail"

	// StrategyHTTPResponse はステータス行＋全ヘッダー＋ボディ先頭Nバイトを残す。
	// curl, wget などのHTTPツール向け。
	StrategyHTTPResponse TruncateStrategy = "http_response"
)

// TruncateConfig は切り捨て設定を保持する。
type TruncateConfig struct {
	Strategy  TruncateStrategy
	HeadLines int // StrategyHeadTail: 先頭から残す行数
	TailLines int // StrategyHeadTail: 末尾から残す行数
	BodyBytes int // StrategyHTTPResponse: ボディ先頭から残すバイト数
}

// DefaultHeadTailConfig は汎用ツール向けのデフォルト設定。
var DefaultHeadTailConfig = TruncateConfig{
	Strategy:  StrategyHeadTail,
	HeadLines: 50,
	TailLines: 30,
}

// DefaultHTTPConfig はHTTPツール向けのデフォルト設定。
var DefaultHTTPConfig = TruncateConfig{
	Strategy:  StrategyHTTPResponse,
	BodyBytes: 500,
}

// Truncate は lines に切り捨て戦略を適用し、Brain へ渡す圧縮済み文字列を返す。
func Truncate(lines []string, cfg TruncateConfig) string {
	switch cfg.Strategy {
	case StrategyHTTPResponse:
		return truncateHTTPResponse(lines, cfg.BodyBytes)
	default:
		return truncateHeadTail(lines, cfg.HeadLines, cfg.TailLines)
	}
}

// truncateHeadTail は先頭 head 行 + 末尾 tail 行を残す。
// 合計行数が head+tail 以下なら全行を返す。
func truncateHeadTail(lines []string, head, tail int) string {
	total := len(lines)
	if total == 0 {
		return ""
	}
	if head+tail >= total {
		return strings.Join(lines, "\n")
	}

	omitted := total - head - tail
	var sb strings.Builder

	for _, l := range lines[:head] {
		sb.WriteString(l)
		sb.WriteByte('\n')
	}
	sb.WriteString(fmt.Sprintf("\n--- %d行省略 ---\n\n", omitted))
	for _, l := range lines[total-tail:] {
		sb.WriteString(l)
		sb.WriteByte('\n')
	}

	return sb.String()
}

// truncateHTTPResponse はHTTPレスポンスを
// ステータス行 + 全ヘッダー + ボディ先頭 bodyBytes バイトに圧縮する。
func truncateHTTPResponse(lines []string, bodyBytes int) string {
	var sb strings.Builder
	inBody := false
	bodyBuf := strings.Builder{}

	for _, line := range lines {
		if !inBody {
			sb.WriteString(line)
			sb.WriteByte('\n')
			// 空行 = ヘッダー終端 → ボディ開始
			if strings.TrimSpace(line) == "" {
				inBody = true
			}
			continue
		}
		// ボディ: bodyBytes に達するまで蓄積
		if bodyBuf.Len() < bodyBytes {
			remaining := bodyBytes - bodyBuf.Len()
			if len(line)+1 <= remaining {
				bodyBuf.WriteString(line)
				bodyBuf.WriteByte('\n')
			} else {
				bodyBuf.WriteString(line[:remaining])
			}
		}
	}

	if bodyBuf.Len() > 0 {
		sb.WriteString(bodyBuf.String())
		if bodyBuf.Len() >= bodyBytes {
			sb.WriteString("\n--- ボディ省略 ---\n")
		}
	}

	return sb.String()
}
