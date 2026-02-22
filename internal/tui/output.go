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

// overwriteOutputLine is a compatibility no-op; full redraw is handled by tcell.
func (a *App) overwriteOutputLine(string) {}

// isThinkingLocked checks if the most recent active block is a Thinking block.
// Must be called with a.mu held.
func (a *App) isThinkingLocked() bool {
	t := a.activeTargetLocked()
	if t == nil {
		return false
	}
	for i := len(t.Blocks) - 1; i >= 0; i-- {
		b := t.Blocks[i]
		if b.Type == agent.BlockThinking && !b.ThinkingDone {
			return true
		}
		if (b.Type == agent.BlockCommand && !b.Completed) ||
			(b.Type == agent.BlockSubTask && !b.TaskDone) {
			return false
		}
	}
	return false
}

// nextSpinnerFrame returns the current spinner animation frame.
func (a *App) nextSpinnerFrame() string {
	if len(a.spinnerFrames) == 0 {
		return "."
	}
	idx := a.spinnerIdx.Load()
	return a.spinnerFrames[int(idx)%len(a.spinnerFrames)]
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
	_, _ = fmt.Fprintln(a.testWriter, fmt.Sprintf("     ... +%d lines (ctrl+o)", remaining))
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

// printProposal emits proposal text only in tests.
func (a *App) printProposal(p *agent.Proposal) {
	if a.testWriter == nil {
		return
	}
	a.mu.Lock()
	lines := a.proposalLinesLocked(p)
	a.mu.Unlock()
	for _, l := range lines {
		_, _ = fmt.Fprintln(a.testWriter, l)
	}
}

// printReconTree appends recon tree output as a system block.
func (a *App) printReconTree(host, treeOutput string) {
	title := "RECON TREE - " + host
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
		a.globalLogs = append(a.globalLogs, "RECON TREE - "+host)
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
