package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/glamour"
	"github.com/charmbracelet/lipgloss"

	"github.com/0x6d61/pentecter/internal/agent"
)

// renderCommandBlock はコマンド実行ブロックをレンダリングする。
// Format:
//
//	● command
//	⎿  output line 1
//	   output line 2
//	   … +N lines (ctrl+o)
func renderCommandBlock(b *agent.DisplayBlock, width int, expanded bool) string {
	var sb strings.Builder

	// コマンドヘッダー（● 付き）
	cmdStyle := lipgloss.NewStyle().Foreground(colorPrimary).Bold(true)
	sb.WriteString(cmdStyle.Render("● " + b.Command))
	sb.WriteString("\n")

	if len(b.Output) == 0 {
		return sb.String()
	}

	// 出力行のプレフィックス
	const outputPrefix = "  ⎿  "
	const contPrefix = "     "
	const cmdFoldThreshold = 5
	const previewLines = 3

	lines := b.Output
	folded := false
	if !expanded && len(lines) > cmdFoldThreshold {
		folded = true
		lines = lines[:previewLines]
	}

	outputStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#AAAAAA"))
	for i, line := range lines {
		prefix := contPrefix
		if i == 0 {
			prefix = outputPrefix
		}
		sb.WriteString(outputStyle.Render(prefix + line))
		sb.WriteString("\n")
	}

	if folded {
		remaining := len(b.Output) - previewLines
		indicator := foldIndicatorStyle.Render(fmt.Sprintf("     … +%d lines (ctrl+o)", remaining))
		sb.WriteString(indicator)
		sb.WriteString("\n")
	}

	return sb.String()
}

// renderThinkingBlock は思考中/処理中ブロックをレンダリングする。
// 処理中: <spinnerFrame> Thinking... (アニメーション付きスピナー)
// 完了: ✻ Completed in Xs
func renderThinkingBlock(b *agent.DisplayBlock, spinnerFrame string) string {
	if b.ThinkingDone {
		dur := formatDuration(b.ThinkDuration)
		style := lipgloss.NewStyle().Foreground(colorSecondary)
		return style.Render(fmt.Sprintf("✻ Completed in %s", dur)) + "\n"
	}
	style := lipgloss.NewStyle().Foreground(colorSecondary)
	return style.Render(spinnerFrame + " Thinking...") + "\n"
}

// renderAIMessageBlock は AI レスポンスブロックをレンダリングする。
// glamour で Markdown をターミナル用にレンダリングする。
func renderAIMessageBlock(b *agent.DisplayBlock, width int) string {
	if b.Message == "" {
		return ""
	}

	// glamour でマークダウンをレンダリング
	rendered, err := renderMarkdown(b.Message, width)
	if err != nil {
		// フォールバック: プレーンテキスト
		return b.Message + "\n"
	}
	return rendered
}

// renderMarkdown は glamour を使って Markdown をターミナル用にレンダリングする。
// ダークスタイルを明示指定（TUI は常にダークターミナルで使用される想定）。
// WithAutoStyle() は非 TTY 環境（テスト・CI）で plain にフォールバックするため使用しない。
// glamour の dark スタイルは左右マージンを追加するため、width を縮小して渡す。
func renderMarkdown(text string, width int) (string, error) {
	// glamour dark スタイルのマージン分を差し引く（左2+右2=4）
	wrapWidth := width - 4
	if wrapWidth < 20 {
		wrapWidth = 20
	}
	r, err := glamour.NewTermRenderer(
		glamour.WithStylePath("dark"),
		glamour.WithWordWrap(wrapWidth),
	)
	if err != nil {
		return "", err
	}
	out, err := r.Render(text)
	if err != nil {
		return "", err
	}
	return out, nil
}

// renderMemoryBlock はメモリ/発見事項ブロックをレンダリングする。
// Format: 📝 [SEVERITY] title
func renderMemoryBlock(b *agent.DisplayBlock) string {
	style := lipgloss.NewStyle().Foreground(colorWarning)
	return style.Render(fmt.Sprintf("📝 [%s] %s", b.Severity, b.Title)) + "\n"
}

// renderSubTaskBlock はサブタスク進捗ブロックをレンダリングする。
// 処理中: <spinnerFrame> goal (アニメーション付きスピナー)
// 完了: ~~goal~~ ✓ Xs (取り消し線)
// width でゴールテキストを折り返す。
func renderSubTaskBlock(b *agent.DisplayBlock, width int, spinnerFrame string) string {
	if width <= 0 {
		width = 80
	}
	if b.TaskDone {
		dur := formatDuration(b.TaskDuration)
		goalStyle := lipgloss.NewStyle().Strikethrough(true).Foreground(colorMuted)
		checkStyle := lipgloss.NewStyle().Foreground(colorSuccess)
		check := checkStyle.Render(fmt.Sprintf(" ✓ %s", dur))
		goal := goalStyle.Render(b.TaskGoal)
		// 1行に収まる場合はそのまま
		if lipgloss.Width(goal)+lipgloss.Width(check) <= width {
			return goal + check + "\n"
		}
		// 収まらない場合はゴールを折り返し、チェックマークを最終行に付与
		return goalStyle.Width(width).Render(b.TaskGoal) + check + "\n"
	}
	prefix := spinnerFrame + " "
	goalW := width - lipgloss.Width(prefix)
	if goalW < 20 {
		goalW = 20
	}
	style := lipgloss.NewStyle().Foreground(colorPrimary)
	wrapped := lipgloss.NewStyle().Width(goalW).Render(b.TaskGoal)
	lines := strings.Split(wrapped, "\n")
	var sb strings.Builder
	indent := strings.Repeat(" ", lipgloss.Width(prefix))
	for i, line := range lines {
		if i == 0 {
			sb.WriteString(style.Render(prefix + line))
		} else {
			sb.WriteString(style.Render(indent + line))
		}
		sb.WriteString("\n")
	}
	return sb.String()
}

// renderUserInputBlock はユーザー入力ブロックをハイライト背景でレンダリングする。
// Format: > text
func renderUserInputBlock(b *agent.DisplayBlock, width int) string {
	style := userInputBlockStyle
	return style.Render("> " + b.UserText) + "\n"
}

// renderSystemBlock はシステムメッセージをレンダリングする。
func renderSystemBlock(b *agent.DisplayBlock) string {
	style := lipgloss.NewStyle().Foreground(colorMuted)
	return style.Render(b.SystemMsg) + "\n"
}

// formatDuration は表示用の時間フォーマットを返す (例: "12s", "1m23s")。
func formatDuration(d time.Duration) string {
	if d < time.Second {
		return "<1s"
	}
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	m := int(d.Minutes())
	s := int(d.Seconds()) - m*60
	return fmt.Sprintf("%dm%ds", m, s)
}

// renderBlocks は全ての DisplayBlock をビューポート用コンテンツにレンダリングする。
// spinnerFrame はアクティブな thinking/subtask ブロックに表示するスピナーの現在フレーム。
func renderBlocks(blocks []*agent.DisplayBlock, width int, expanded bool, spinnerFrame string) string {
	var sb strings.Builder
	for _, b := range blocks {
		switch b.Type {
		case agent.BlockCommand:
			sb.WriteString(renderCommandBlock(b, width, expanded))
		case agent.BlockThinking:
			sb.WriteString(renderThinkingBlock(b, spinnerFrame))
		case agent.BlockAIMessage:
			sb.WriteString(renderAIMessageBlock(b, width))
		case agent.BlockMemory:
			sb.WriteString(renderMemoryBlock(b))
		case agent.BlockSubTask:
			sb.WriteString(renderSubTaskBlock(b, width, spinnerFrame))
		case agent.BlockUserInput:
			sb.WriteString(renderUserInputBlock(b, width))
		case agent.BlockSystem:
			sb.WriteString(renderSystemBlock(b))
		}
	}
	return sb.String()
}
