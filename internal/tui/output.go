package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

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
			a.enqueueUIEvent(uiEventMsg{kind: uiEventSpinnerTick})
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
	if a.testWriter != nil {
		a.clearAndReprint()
	}
}

// clearAndReprint emits current active target text only in tests.
func (a *App) clearAndReprint() {
	if a.testWriter == nil {
		return
	}

	a.mu.Lock()
	width := a.width
	if width <= 0 {
		width = defaultWidth
	}
	lines := a.buildOutputLinesLocked(width)
	a.mu.Unlock()

	for _, l := range lines {
		_, _ = fmt.Fprintln(a.testWriter, l)
	}
}

// printAttackData appends attack data tree output as a system block.
func (a *App) printAttackData(host, treeOutput string) {
	title := "ATTACK DATA - " + host
	body := strings.Split(treeOutput, "\n")
	rows := append([]string{title}, body...)

	maxW := 0
	for _, row := range rows {
		if w := runeLen(row); w > maxW {
			maxW = w
		}
	}
	if maxW < 1 {
		maxW = 1
	}

	var b strings.Builder
	b.WriteString("╭")
	b.WriteString(strings.Repeat("─", maxW+2))
	b.WriteString("╮\n")
	for i, row := range rows {
		pad := maxW - runeLen(row)
		if pad < 0 {
			pad = 0
		}
		b.WriteString("│ ")
		b.WriteString(row)
		b.WriteString(strings.Repeat(" ", pad))
		b.WriteString(" │")
		if i < len(rows)-1 {
			b.WriteString("\n")
		}
	}
	b.WriteString("\n╰")
	b.WriteString(strings.Repeat("─", maxW+2))
	b.WriteString("╯")

	msg := b.String()

	a.mu.Lock()
	if t := a.activeTargetLocked(); t != nil {
		t.AddBlock(agent.NewSystemBlock(msg))
	} else {
		a.globalLogs = append(a.globalLogs, "ATTACK DATA - "+host)
		a.globalLogs = append(a.globalLogs, strings.Split(treeOutput, "\n")...)
	}
	a.invalidateOutputCacheLocked()
	if a.testWriter != nil {
		_, _ = fmt.Fprintln(a.testWriter, msg)
	}
	a.mu.Unlock()
}

// printStatusLine writes current status into the log stream.
func (a *App) printStatusLine() {
	status := a.buildStatusText()
	if status == "" {
		status = "No active target/model status."
	}
	a.logSystem(status)
}
