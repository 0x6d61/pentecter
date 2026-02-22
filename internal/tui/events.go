package tui

import (
	"context"
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/0x6d61/pentecter/internal/agent"
)

// consumeEvents runs in a goroutine and processes all agent events.
func (a *App) consumeEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case e, ok := <-a.agentEvents:
			if !ok {
				return
			}
			a.handleAgentEvent(e)
		}
	}
}

// handleAgentEvent processes a single agent event.
// It updates blocks under lock, then prints output without holding the lock.
func (a *App) handleAgentEvent(e agent.Event) {
	t := a.targetByID(e.TargetID)
	if t == nil {
		t = a.activeTarget()
	}
	if t == nil {
		return
	}

	active := a.activeTarget()
	isActive := active != nil && t.ID == active.ID
	w := a.writer()
	width := a.width

	switch e.Type {
	case agent.EventLog:
		switch e.Source {
		case agent.SourceAI:
			block := agent.NewAIMessageBlock(e.Message)
			a.mu.Lock()
			t.AddBlock(block)
			a.mu.Unlock()
			if isActive {
				_, _ = fmt.Fprint(w, renderAIMessageBlock(block, width))
			}

		case agent.SourceTool:
			a.mu.Lock()
			last := t.LastBlock()
			if last != nil && last.Type == agent.BlockCommand && !last.Completed {
				last.Output = append(last.Output, e.Message)
				a.mu.Unlock()
				if isActive {
					_, _ = fmt.Fprintln(w, outputStyle.Render("     "+e.Message))
				}
			} else {
				block := agent.NewCommandBlock(e.Message)
				t.AddBlock(block)
				a.mu.Unlock()
				if isActive {
					_, _ = fmt.Fprint(w, renderCommandBlock(block, width, false))
				}
			}

		case agent.SourceSystem:
			block := agent.NewSystemBlock(e.Message)
			a.mu.Lock()
			t.AddBlock(block)
			a.mu.Unlock()
			if isActive {
				_, _ = fmt.Fprint(w, renderSystemBlock(block))
			}

		case agent.SourceUser:
			block := agent.NewUserInputBlock(e.Message)
			a.mu.Lock()
			t.AddBlock(block)
			a.mu.Unlock()
			if isActive {
				_, _ = fmt.Fprint(w, renderUserInputBlock(block, width))
			}
		}

	case agent.EventProposal:
		if e.Proposal != nil {
			t.SetProposal(e.Proposal)
			if isActive {
				a.printProposal(e.Proposal)
				a.inputMode = ModeProposal
				a.refreshPrompt()
			}
		}

	case agent.EventComplete:
		block := agent.NewSystemBlock("✅ " + e.Message)
		a.mu.Lock()
		t.AddBlock(block)
		a.mu.Unlock()
		if isActive {
			_, _ = fmt.Fprint(w, renderSystemBlock(block))
		}

	case agent.EventError:
		block := agent.NewSystemBlock("❌ " + e.Message)
		a.mu.Lock()
		t.AddBlock(block)
		a.mu.Unlock()
		if isActive {
			_, _ = fmt.Fprint(w, renderSystemBlock(block))
		}

	case agent.EventAddTarget:
		if e.NewHost != "" && a.team != nil {
			a.addTarget(e.NewHost)
		}

	case agent.EventStalled:
		block1 := agent.NewSystemBlock("⚠ " + e.Message)
		block2 := agent.NewSystemBlock("Type a message to give the agent new direction.")
		a.mu.Lock()
		t.AddBlock(block1)
		t.AddBlock(block2)
		a.mu.Unlock()
		if isActive {
			_, _ = fmt.Fprint(w, renderSystemBlock(block1))
			_, _ = fmt.Fprint(w, renderSystemBlock(block2))
		}

	case agent.EventTurnStart:
		// No display action needed

	case agent.EventThinkStart:
		block := agent.NewThinkingBlock()
		a.mu.Lock()
		t.AddBlock(block)
		a.mu.Unlock()
		if isActive {
			// Print initial spinner line to output area (will be animated by runSpinner)
			style := lipgloss.NewStyle().Foreground(colorSecondary)
			_, _ = fmt.Fprintln(w, style.Render("⠋ Thinking..."))
		}
		a.spinnerActive.Store(true)

	case agent.EventThinkDone:
		a.mu.Lock()
		last := t.LastBlock()
		if last != nil && last.Type == agent.BlockThinking && !last.ThinkingDone {
			last.ThinkingDone = true
			last.ThinkDuration = e.Duration
			a.mu.Unlock()
			if isActive {
				// Overwrite the spinner line with completion text
				rendered := strings.TrimSuffix(renderThinkingBlock(last, ""), "\n")
				a.overwriteOutputLine(rendered)
			}
		} else {
			a.mu.Unlock()
		}
		a.updateSpinnerState()

	case agent.EventCmdStart:
		a.mu.Lock()
		t.AddBlock(agent.NewCommandBlock(e.Message))
		a.mu.Unlock()
		if isActive {
			cmdStyle := lipgloss.NewStyle().Foreground(colorPrimary).Bold(true)
			_, _ = fmt.Fprintln(w, cmdStyle.Render("● "+e.Message))
		}

	case agent.EventCmdOutput:
		a.mu.Lock()
		last := t.LastBlock()
		if last != nil && last.Type == agent.BlockCommand && !last.Completed {
			last.Output = append(last.Output, e.OutputLine)
			outputLen := len(last.Output)
			a.mu.Unlock()
			if isActive {
				prefix := "     "
				if outputLen == 1 {
					prefix = "  ⎿  "
				}
				_, _ = fmt.Fprintln(w, outputStyle.Render(prefix+e.OutputLine))
			}
		} else {
			a.mu.Unlock()
		}

	case agent.EventCmdDone:
		a.mu.Lock()
		last := t.LastBlock()
		if last != nil && last.Type == agent.BlockCommand {
			last.Completed = true
			last.ExitCode = e.ExitCode
			last.Duration = e.Duration
		}
		a.mu.Unlock()
		a.updateSpinnerState()

	case agent.EventSubTaskStart:
		a.mu.Lock()
		t.AddBlock(agent.NewSubTaskBlock(e.TaskID, e.Message))
		a.mu.Unlock()
		a.spinnerActive.Store(true)

	case agent.EventSubTaskLog:
		// Internal processing, no display

	case agent.EventSubTaskComplete:
		a.mu.Lock()
		for i := len(t.Blocks) - 1; i >= 0; i-- {
			b := t.Blocks[i]
			if b.Type == agent.BlockSubTask && b.TaskID == e.TaskID && !b.TaskDone {
				b.TaskDone = true
				b.TaskDuration = e.Duration
				a.mu.Unlock()
				if isActive {
					_, _ = fmt.Fprint(w, renderSubTaskBlock(b, width, ""))
				}
				a.updateSpinnerState()
				return
			}
		}
		a.mu.Unlock()
		a.updateSpinnerState()
	}
}

// updateSpinnerState checks if there are active blocks and updates the spinner.
func (a *App) updateSpinnerState() {
	a.mu.Lock()
	hasActive := a.hasActiveBlocksLocked()
	a.mu.Unlock()

	if hasActive {
		a.spinnerActive.Store(true)
	} else {
		a.spinnerActive.Store(false)
		a.refreshPrompt()
	}
}

// hasActiveBlocksLocked checks if there are active blocks. Must be called with a.mu held.
func (a *App) hasActiveBlocksLocked() bool {
	t := a.activeTarget()
	if t == nil {
		return false
	}
	for i := len(t.Blocks) - 1; i >= 0; i-- {
		b := t.Blocks[i]
		switch b.Type {
		case agent.BlockThinking:
			if !b.ThinkingDone {
				return true
			}
		case agent.BlockSubTask:
			if !b.TaskDone {
				return true
			}
		case agent.BlockCommand:
			if !b.Completed {
				return true
			}
		}
	}
	return false
}
