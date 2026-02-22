package tui

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/0x6d61/pentecter/internal/agent"
)

func TestHandleAgentEvent_EventLog_AI(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	var buf bytes.Buffer
	a := NewApp([]*agent.Target{target})
	a.testWriter = &buf

	a.handleAgentEvent(agent.Event{
		TargetID: 1,
		Type:     agent.EventLog,
		Source:   agent.SourceAI,
		Message:  "Based on scan results...",
	})

	if len(target.Blocks) != 1 {
		t.Fatalf("expected 1 block, got %d", len(target.Blocks))
	}
	if target.Blocks[0].Type != agent.BlockAIMessage {
		t.Errorf("expected BlockAIMessage, got %d", target.Blocks[0].Type)
	}
}

func TestHandleAgentEvent_EventLog_System(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	var buf bytes.Buffer
	a := NewApp([]*agent.Target{target})
	a.testWriter = &buf

	a.handleAgentEvent(agent.Event{
		TargetID: 1,
		Type:     agent.EventLog,
		Source:   agent.SourceSystem,
		Message:  "System message",
	})

	if len(target.Blocks) != 1 {
		t.Fatalf("expected 1 block, got %d", len(target.Blocks))
	}
	if target.Blocks[0].Type != agent.BlockSystem {
		t.Errorf("expected BlockSystem, got %d", target.Blocks[0].Type)
	}
}

func TestHandleAgentEvent_EventLog_User(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	var buf bytes.Buffer
	a := NewApp([]*agent.Target{target})
	a.testWriter = &buf

	a.handleAgentEvent(agent.Event{
		TargetID: 1,
		Type:     agent.EventLog,
		Source:   agent.SourceUser,
		Message:  "scan ports",
	})

	if len(target.Blocks) != 1 {
		t.Fatalf("expected 1 block, got %d", len(target.Blocks))
	}
	if target.Blocks[0].Type != agent.BlockUserInput {
		t.Errorf("expected BlockUserInput, got %d", target.Blocks[0].Type)
	}
}

func TestHandleAgentEvent_EventThinkStartDone(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	var buf bytes.Buffer
	a := NewApp([]*agent.Target{target})
	a.testWriter = &buf

	a.handleAgentEvent(agent.Event{
		TargetID: 1,
		Type:     agent.EventThinkStart,
	})

	if len(target.Blocks) != 1 {
		t.Fatalf("expected 1 block, got %d", len(target.Blocks))
	}
	if target.Blocks[0].Type != agent.BlockThinking {
		t.Errorf("expected BlockThinking, got %d", target.Blocks[0].Type)
	}
	if !a.spinnerActive.Load() {
		t.Error("expected spinnerActive=true after ThinkStart")
	}

	a.handleAgentEvent(agent.Event{
		TargetID: 1,
		Type:     agent.EventThinkDone,
		Duration: 5 * time.Second,
	})

	if !target.Blocks[0].ThinkingDone {
		t.Error("expected ThinkingDone=true after ThinkDone")
	}
	if target.Blocks[0].ThinkDuration != 5*time.Second {
		t.Errorf("expected ThinkDuration=5s, got %v", target.Blocks[0].ThinkDuration)
	}
	if a.spinnerActive.Load() {
		t.Error("expected spinnerActive=false after ThinkDone")
	}
}

func TestHandleAgentEvent_EventCmdStartOutputDone(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	var buf bytes.Buffer
	a := NewApp([]*agent.Target{target})
	a.testWriter = &buf

	a.handleAgentEvent(agent.Event{
		TargetID: 1,
		Type:     agent.EventCmdStart,
		Message:  "nmap -sV 10.0.0.1",
	})

	if len(target.Blocks) != 1 {
		t.Fatalf("expected 1 block, got %d", len(target.Blocks))
	}
	if target.Blocks[0].Command != "nmap -sV 10.0.0.1" {
		t.Errorf("expected command text, got %q", target.Blocks[0].Command)
	}

	a.handleAgentEvent(agent.Event{
		TargetID:   1,
		Type:       agent.EventCmdOutput,
		OutputLine: "22/tcp open ssh",
	})
	a.handleAgentEvent(agent.Event{
		TargetID:   1,
		Type:       agent.EventCmdOutput,
		OutputLine: "80/tcp open http",
	})

	if len(target.Blocks[0].Output) != 2 {
		t.Fatalf("expected 2 output lines, got %d", len(target.Blocks[0].Output))
	}

	a.handleAgentEvent(agent.Event{
		TargetID: 1,
		Type:     agent.EventCmdDone,
		ExitCode: 0,
		Duration: 3 * time.Second,
	})

	if !target.Blocks[0].Completed {
		t.Error("expected Completed=true after CmdDone")
	}
	if target.Blocks[0].ExitCode != 0 {
		t.Errorf("expected ExitCode=0, got %d", target.Blocks[0].ExitCode)
	}

	output := buf.String()
	if !strings.Contains(output, "nmap -sV 10.0.0.1") {
		t.Error("expected command header in output")
	}
	if !strings.Contains(output, "22/tcp open ssh") {
		t.Error("expected first output line in output")
	}
}

func TestHandleAgentEvent_EventProposal(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	var buf bytes.Buffer
	a := NewApp([]*agent.Target{target})
	a.testWriter = &buf

	a.handleAgentEvent(agent.Event{
		TargetID: 1,
		Type:     agent.EventProposal,
		Proposal: &agent.Proposal{
			Description: "Run nmap scan",
			Tool:        "nmap",
			Args:        []string{"-sV", "10.0.0.1"},
		},
	})

	if target.GetProposal() == nil {
		t.Error("expected proposal to be set")
	}
	if a.inputMode != ModeProposal {
		t.Errorf("expected ModeProposal, got %d", a.inputMode)
	}
}

func TestHandleAgentEvent_EventComplete(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	var buf bytes.Buffer
	a := NewApp([]*agent.Target{target})
	a.testWriter = &buf

	a.handleAgentEvent(agent.Event{
		TargetID: 1,
		Type:     agent.EventComplete,
		Message:  "Assessment complete",
	})

	if len(target.Blocks) != 1 {
		t.Fatalf("expected 1 block, got %d", len(target.Blocks))
	}
	if !strings.Contains(target.Blocks[0].SystemMsg, "Assessment complete") {
		t.Errorf("expected completion message, got %q", target.Blocks[0].SystemMsg)
	}
}

func TestHandleAgentEvent_EventError(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	var buf bytes.Buffer
	a := NewApp([]*agent.Target{target})
	a.testWriter = &buf

	a.handleAgentEvent(agent.Event{
		TargetID: 1,
		Type:     agent.EventError,
		Message:  "Connection failed",
	})

	if len(target.Blocks) != 1 {
		t.Fatalf("expected 1 block, got %d", len(target.Blocks))
	}
	if !strings.Contains(target.Blocks[0].SystemMsg, "Connection failed") {
		t.Errorf("expected error message, got %q", target.Blocks[0].SystemMsg)
	}
}

func TestHandleAgentEvent_EventStalled(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	var buf bytes.Buffer
	a := NewApp([]*agent.Target{target})
	a.testWriter = &buf

	a.handleAgentEvent(agent.Event{
		TargetID: 1,
		Type:     agent.EventStalled,
		Message:  "Agent is stuck",
	})

	if len(target.Blocks) != 2 {
		t.Fatalf("expected 2 blocks (stall + guidance), got %d", len(target.Blocks))
	}
}

func TestHandleAgentEvent_EventSubTaskStartComplete(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	var buf bytes.Buffer
	a := NewApp([]*agent.Target{target})
	a.testWriter = &buf

	a.handleAgentEvent(agent.Event{
		TargetID: 1,
		Type:     agent.EventSubTaskStart,
		TaskID:   "task-1",
		Message:  "Enumerate web endpoints",
	})

	if len(target.Blocks) != 1 {
		t.Fatalf("expected 1 block, got %d", len(target.Blocks))
	}
	if target.Blocks[0].Type != agent.BlockSubTask {
		t.Errorf("expected BlockSubTask, got %d", target.Blocks[0].Type)
	}
	if !a.spinnerActive.Load() {
		t.Error("expected spinnerActive=true after SubTaskStart")
	}

	a.handleAgentEvent(agent.Event{
		TargetID: 1,
		Type:     agent.EventSubTaskComplete,
		TaskID:   "task-1",
		Duration: 8 * time.Second,
	})

	if !target.Blocks[0].TaskDone {
		t.Error("expected TaskDone=true after SubTaskComplete")
	}
	if a.spinnerActive.Load() {
		t.Error("expected spinnerActive=false after SubTaskComplete")
	}
}

func TestHandleAgentEvent_NilTarget(t *testing.T) {
	a := NewApp(nil)
	a.testWriter = &bytes.Buffer{}

	// Should not panic
	a.handleAgentEvent(agent.Event{
		TargetID: 99,
		Type:     agent.EventLog,
		Source:   agent.SourceSystem,
		Message:  "test",
	})
}

func TestHasActiveBlocksLocked_NoBlocks(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	a := NewApp([]*agent.Target{target})

	a.mu.Lock()
	result := a.hasActiveBlocksLocked()
	a.mu.Unlock()

	if result {
		t.Error("expected false for no blocks")
	}
}

func TestHasActiveBlocksLocked_ActiveThinking(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	target.AddBlock(agent.NewThinkingBlock())
	a := NewApp([]*agent.Target{target})

	a.mu.Lock()
	result := a.hasActiveBlocksLocked()
	a.mu.Unlock()

	if !result {
		t.Error("expected true for active thinking block")
	}
}

func TestHasActiveBlocksLocked_CompletedThinking(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	b := agent.NewThinkingBlock()
	b.ThinkingDone = true
	target.AddBlock(b)
	a := NewApp([]*agent.Target{target})

	a.mu.Lock()
	result := a.hasActiveBlocksLocked()
	a.mu.Unlock()

	if result {
		t.Error("expected false for completed thinking block")
	}
}
