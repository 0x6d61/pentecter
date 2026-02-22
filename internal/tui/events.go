package tui

import (
	"context"
	"fmt"

	"github.com/0x6d61/pentecter/internal/agent"
)

// consumeEvents forwards all agent events into the UI event queue.
func (a *App) consumeEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case e, ok := <-a.agentEvents:
			if !ok {
				return
			}
			a.enqueueUIEvent(uiEventMsg{kind: uiEventAgent, agent: e})
		}
	}
}

// handleAgentEvent mutates target/app state only.
// Rendering happens in the single tcell loop.
func (a *App) handleAgentEvent(e agent.Event) {
	a.mu.Lock()
	t := a.targetByIDLocked(e.TargetID)
	if t == nil {
		a.mu.Unlock()
		return
	}
	active := a.activeTargetLocked()
	isActive := active != nil && active.ID == t.ID
	spinnerStateChanged := false
	displayChanged := false

	switch e.Type {
	case agent.EventLog:
		switch e.Source {
		case agent.SourceAI:
			t.AddBlock(agent.NewAIMessageBlock(e.Message))
			displayChanged = true
		case agent.SourceTool:
			last := t.LastBlock()
			if last != nil && last.Type == agent.BlockCommand && !last.Completed {
				last.Output = append(last.Output, e.Message)
			} else {
				t.AddBlock(agent.NewCommandBlock(e.Message))
			}
			displayChanged = true
		case agent.SourceSystem:
			t.AddBlock(agent.NewSystemBlock(e.Message))
			displayChanged = true
		case agent.SourceUser:
			t.AddBlock(agent.NewUserInputBlock(e.Message))
			displayChanged = true
		}

	case agent.EventProposal:
		if e.Proposal != nil {
			t.SetProposal(e.Proposal)
			displayChanged = true
			if isActive {
				a.inputMode = ModeProposal
			}
		}

	case agent.EventComplete:
		t.AddBlock(agent.NewSystemBlock("✓ " + e.Message))
		displayChanged = true

	case agent.EventError:
		t.AddBlock(agent.NewSystemBlock("✗ " + e.Message))
		displayChanged = true

	case agent.EventAddTarget:
		// handled outside lock below

	case agent.EventStalled:
		t.AddBlock(agent.NewSystemBlock("⚠ " + e.Message))
		t.AddBlock(agent.NewSystemBlock("Type a message to give the agent new direction."))
		displayChanged = true

	case agent.EventTurnStart:
		// no-op

	case agent.EventThinkStart:
		t.AddBlock(agent.NewThinkingBlock())
		a.spinnerActive.Store(true)
		spinnerStateChanged = true
		displayChanged = true

	case agent.EventThinkDone:
		last := t.LastBlock()
		if last != nil && last.Type == agent.BlockThinking && !last.ThinkingDone {
			last.ThinkingDone = true
			last.ThinkDuration = e.Duration
			displayChanged = true
		}
		spinnerStateChanged = true

	case agent.EventCmdStart:
		t.AddBlock(agent.NewCommandBlock(e.Message))
		spinnerStateChanged = true
		displayChanged = true

	case agent.EventCmdOutput:
		last := t.LastBlock()
		if last != nil && last.Type == agent.BlockCommand && !last.Completed {
			last.Output = append(last.Output, e.OutputLine)
			displayChanged = true
		}

	case agent.EventCmdDone:
		last := t.LastBlock()
		if last != nil && last.Type == agent.BlockCommand {
			last.Completed = true
			last.ExitCode = e.ExitCode
			last.Duration = e.Duration
			displayChanged = true
		}
		spinnerStateChanged = true

	case agent.EventSubTaskStart:
		t.AddBlock(agent.NewSubTaskBlock(e.TaskID, e.Message))
		a.spinnerActive.Store(true)
		spinnerStateChanged = true
		displayChanged = true

	case agent.EventSubTaskLog:
		// internal-only

	case agent.EventSubTaskComplete:
		for i := len(t.Blocks) - 1; i >= 0; i-- {
			b := t.Blocks[i]
			if b.Type == agent.BlockSubTask && b.TaskID == e.TaskID && !b.TaskDone {
				b.TaskDone = true
				b.TaskDuration = e.Duration
				displayChanged = true
				break
			}
		}
		spinnerStateChanged = true
	}

	addTargetHost := ""
	if e.Type == agent.EventAddTarget {
		addTargetHost = e.NewHost
	}
	if displayChanged {
		a.invalidateOutputCacheLocked()
	}

	a.mu.Unlock()

	if addTargetHost != "" && a.team != nil {
		a.addTarget(addTargetHost)
	}

	if spinnerStateChanged {
		a.updateSpinnerState()
	}

	if a.testWriter != nil {
		a.clearAndReprint()
	}
}

// updateSpinnerState checks if there are active blocks and updates the spinner.
func (a *App) updateSpinnerState() {
	a.mu.Lock()
	hasActive := a.hasActiveBlocksLocked()
	a.mu.Unlock()

	a.spinnerActive.Store(hasActive)
}

// hasActiveBlocksLocked checks if there are active blocks. Must be called with a.mu held.
func (a *App) hasActiveBlocksLocked() bool {
	t := a.activeTargetLocked()
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

func (a *App) debugEventString(e agent.Event) string {
	return fmt.Sprintf("event=%s target=%d", e.Type, e.TargetID)
}
