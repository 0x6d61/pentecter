package tui

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"

	"github.com/0x6d61/pentecter/internal/agent"
)

// runSpinner runs the spinner animation goroutine.
// Animates the spinner text in the output area (above the prompt divider)
// by overwriting the last output line using ANSI escape sequences.
// The input prompt always remains just "> ".
func (a *App) runSpinner(ctx context.Context) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if a.rl == nil || a.testWriter != nil {
				continue
			}

			if !a.spinnerActive.Load() || a.inputMode != ModeNormal {
				continue
			}

			// Only animate for Thinking blocks (no concurrent output conflicts).
			// Commands and SubTasks have their own output flowing.
			a.mu.Lock()
			thinking := a.isThinkingLocked()
			a.mu.Unlock()

			if thinking {
				frame := a.nextSpinnerFrame()
				style := lipgloss.NewStyle().Foreground(colorSecondary)
				a.overwriteOutputLine(style.Render(frame + " Thinking..."))
			}
		}
	}
}

// overwriteOutputLine overwrites the last output line (above the prompt)
// using DEC cursor save/restore. Dynamically calculates prompt height
// to determine how many lines to move up from the cursor.
func (a *App) overwriteOutputLine(styledText string) {
	if a.testWriter != nil {
		return
	}
	n := a.promptEchoLines("")
	if n <= 0 {
		return
	}
	a.outputMu.Lock()
	_, _ = fmt.Fprintf(os.Stdout, "\0337\033[%dA\r\033[K%s\0338", n, styledText)
	a.outputMu.Unlock()
}

// isThinkingLocked checks if the most recent active block is a Thinking block.
// Must be called with a.mu held.
func (a *App) isThinkingLocked() bool {
	t := a.activeTarget()
	if t == nil {
		return false
	}
	for i := len(t.Blocks) - 1; i >= 0; i-- {
		b := t.Blocks[i]
		if b.Type == agent.BlockThinking && !b.ThinkingDone {
			return true
		}
		// Stop at first incomplete non-thinking block
		if (b.Type == agent.BlockCommand && !b.Completed) ||
			(b.Type == agent.BlockSubTask && !b.TaskDone) {
			return false
		}
	}
	return false
}

// nextSpinnerFrame returns the next spinner animation frame.
func (a *App) nextSpinnerFrame() string {
	if len(a.spinnerFrames) == 0 {
		return "⠋"
	}
	idx := a.spinnerIdx.Add(1) - 1
	return a.spinnerFrames[int(idx)%len(a.spinnerFrames)]
}

// toggleFold toggles log folding and reprints all blocks.
func (a *App) toggleFold() {
	a.logsExpanded = !a.logsExpanded
	a.clearAndReprint()
}

// clearAndReprint clears the screen and reprints all blocks for the active target.
func (a *App) clearAndReprint() {
	if a.testWriter == nil {
		// Clear screen and move cursor to home
		_, _ = fmt.Fprint(a.rl.Stdout(), "\033[2J\033[H")
	} else if a.rl != nil {
		a.rl.ClearScreen()
	}

	t := a.activeTarget()
	if t == nil {
		a.printWelcome()
		return
	}

	w := a.writer()
	width := a.width
	expanded := a.logsExpanded

	frame := ""
	if a.spinnerActive.Load() {
		frame = a.spinnerFrames[int(a.spinnerIdx.Load())%len(a.spinnerFrames)]
	}

	a.mu.Lock()
	blocks := make([]*agent.DisplayBlock, len(t.Blocks))
	copy(blocks, t.Blocks)
	a.mu.Unlock()

	for _, b := range blocks {
		rendered := renderBlock(b, width, expanded, frame)
		_, _ = fmt.Fprint(w, rendered)
	}

	// Print proposal if active
	if p := t.GetProposal(); p != nil {
		a.printProposal(p)
	}
}

// printProposal prints the proposal box to stdout.
func (a *App) printProposal(p *agent.Proposal) {
	w := a.writer()

	proposalTitle := lipgloss.NewStyle().
		Foreground(colorWarning).
		Bold(true).
		Render("⚠  PROPOSAL — Awaiting approval")

	proposalBody := fmt.Sprintf(
		"%s\n  Tool: %s %s",
		p.Description,
		p.Tool,
		strings.Join(p.Args, " "),
	)

	proposalControls := lipgloss.NewStyle().
		Foreground(colorMuted).
		Render("  [y] Approve  [n] Reject  [e] Edit")

	boxWidth := a.width - 4
	if boxWidth < 10 {
		boxWidth = 10
	}

	box := proposalBoxStyle.Width(boxWidth).Render(
		proposalTitle + "\n\n  " + proposalBody + "\n\n" + proposalControls,
	)
	_, _ = fmt.Fprintln(w, box)
}

// printReconTree prints the recon tree in a styled box.
func (a *App) printReconTree(host, treeOutput string) {
	w := a.writer()

	title := lipgloss.NewStyle().
		Foreground(colorPrimary).
		Bold(true).
		Render("RECON TREE — " + host)

	boxWidth := a.width - 4
	if boxWidth < 10 {
		boxWidth = 10
	}

	box := reconBoxStyle.Width(boxWidth).Render(
		title + "\n\n" + treeOutput,
	)
	_, _ = fmt.Fprintln(w, box)
}

// printStatusLine prints the status line.
func (a *App) printStatusLine() {
	w := a.writer()
	t := a.activeTarget()

	appName := lipgloss.NewStyle().Foreground(colorPrimary).Bold(true).Render("⚡ PENTECTER")

	var parts []string
	parts = append(parts, appName)

	if t != nil {
		parts = append(parts, fmt.Sprintf("%s [%s]",
			lipgloss.NewStyle().Foreground(colorWarning).Render(t.Host),
			t.GetStatus()))
	}

	if a.CurrentModel != "" {
		parts = append(parts, lipgloss.NewStyle().Foreground(colorMuted).Render(
			a.CurrentProvider+"/"+a.CurrentModel))
	}

	line := strings.Join(parts, " | ")
	_, _ = fmt.Fprintln(w, statusBarStyle.Width(a.width).Render(line))
}
