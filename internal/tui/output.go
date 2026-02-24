package tui

import (
	"context"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/0x6d61/pentecter/internal/agent"
)

// runSpinner posts spinner tick events to the single UI loop.
func (a *App) runSpinner(ctx context.Context) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !a.spinnerActive.Load() {
				continue
			}
			a.spinnerIdx.Add(1)
		}
	}
}

// printCmdOutputLine emits textual output only in tests.
func (a *App) printCmdOutputLine(line string, outputLen int) {
	if a.testWriter == nil {
		return
	}

	a.mu.Lock()
	expanded := a.logsExpanded
	a.mu.Unlock()

	prefix := "     "
	if outputLen == 1 {
		prefix = "  ⎿  "
	}

	if expanded || outputLen <= cmdFoldThreshold {
		_, _ = fmt.Fprintln(a.testWriter, prefix+line)
		return
	}

	remaining := outputLen - previewLines
	_, _ = fmt.Fprintf(a.testWriter, "     ... +%d lines (ctrl+o)\n", remaining)
}

// toggleFold toggles log folding.
func (a *App) toggleFold() {
	a.mu.Lock()
	a.logsExpanded = !a.logsExpanded
	a.mu.Unlock()
	a.clearAndReprint()
}

// toggleThinkingFold toggles thinking block visibility.
func (a *App) toggleThinkingFold() {
	a.mu.Lock()
	a.thinkingExpanded = !a.thinkingExpanded
	a.mu.Unlock()
	a.clearAndReprint()
}

// printAttackData appends attack data tree output as a system block.
func (a *App) printAttackData(host, treeOutput string) {
	a.mu.Lock()
	width := a.width
	a.mu.Unlock()
	if width <= 0 {
		width = defaultWidth
	}

	maxContentWidth := width - 4 // "| " + " |"
	if maxContentWidth < 1 {
		maxContentWidth = 1
	}

	body := strings.Split(treeOutput, "\n")
	rows := make([]string, 0, len(body)+1)
	rows = append(rows, trimToDisplayWidth(sanitizeAttackDataRow("ATTACK DATA - "+host), maxContentWidth))
	for _, row := range body {
		rows = append(rows, trimToDisplayWidth(sanitizeAttackDataRow(row), maxContentWidth))
	}

	maxW := 1
	for _, row := range rows {
		if w := displayWidth(row); w > maxW {
			maxW = w
		}
	}

	var b strings.Builder
	b.WriteString("+")
	b.WriteString(strings.Repeat("-", maxW+2))
	b.WriteString("+\n")
	for i, row := range rows {
		b.WriteString("| ")
		b.WriteString(padRightDisplayWidth(row, maxW))
		b.WriteString(" |")
		if i < len(rows)-1 {
			b.WriteString("\n")
		}
	}
	b.WriteString("\n+")
	b.WriteString(strings.Repeat("-", maxW+2))
	b.WriteString("+")

	msg := b.String()

	a.mu.Lock()
	if t := a.activeTargetLocked(); t != nil {
		t.AddBlock(agent.NewSystemBlock(msg))
	} else {
		a.globalLogs = append(a.globalLogs, "ATTACK DATA - "+host)
		a.globalLogs = append(a.globalLogs, strings.Split(treeOutput, "\n")...)
	}
	a.invalidateOutputCacheLocked()
	a.mu.Unlock()
	a.clearAndReprint()
}

func sanitizeAttackDataRow(s string) string {
	if s == "" {
		return ""
	}

	var b strings.Builder
	lastWasSpace := false
	for _, r := range s {
		switch {
		case r == '\r' || r == '\n' || r == '\t':
			if !lastWasSpace {
				b.WriteByte(' ')
				lastWasSpace = true
			}
		case unicode.IsControl(r):
			// Drop control characters from display-only output.
		default:
			b.WriteRune(r)
			lastWasSpace = r == ' '
		}
	}
	return strings.TrimRight(b.String(), " ")
}

func trimToDisplayWidth(s string, maxWidth int) string {
	if maxWidth <= 0 {
		return ""
	}
	if displayWidth(s) <= maxWidth {
		return s
	}

	const ellipsis = "..."
	ellipsisWidth := displayWidth(ellipsis)

	limit := maxWidth
	appendEllipsis := false
	if maxWidth > ellipsisWidth {
		limit = maxWidth - ellipsisWidth
		appendEllipsis = true
	}

	var b strings.Builder
	curW := 0
	for _, r := range s {
		rw := displayWidth(string(r))
		if rw == 0 {
			b.WriteRune(r)
			continue
		}
		if curW+rw > limit {
			break
		}
		b.WriteRune(r)
		curW += rw
	}
	if appendEllipsis {
		b.WriteString(ellipsis)
	}
	return b.String()
}

func padRightDisplayWidth(s string, width int) string {
	pad := width - displayWidth(s)
	if pad <= 0 {
		return s
	}
	return s + strings.Repeat(" ", pad)
}

// printStatusLine writes current status into the log stream.
func (a *App) printStatusLine() {
	status := a.buildStatusText()
	if status == "" {
		status = "No active target/model status."
	}
	a.logSystem(status)
}
