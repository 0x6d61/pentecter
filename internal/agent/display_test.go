package agent_test

import (
	"testing"
	"time"

	"github.com/0x6d61/pentecter/internal/agent"
)

// TestBlockType_IotaValues は各 BlockType 定数が正しい iota 値を持つことを確認する。
func TestBlockType_IotaValues(t *testing.T) {
	tests := []struct {
		name string
		got  agent.BlockType
		want int
	}{
		{"BlockCommand", agent.BlockCommand, 0},
		{"BlockThinking", agent.BlockThinking, 1},
		{"BlockAIMessage", agent.BlockAIMessage, 2},
		{"BlockMemory", agent.BlockMemory, 3},
		{"BlockSubTask", agent.BlockSubTask, 4},
		{"BlockUserInput", agent.BlockUserInput, 5},
		{"BlockSystem", agent.BlockSystem, 6},
	}

	for _, tt := range tests {
		if int(tt.got) != tt.want {
			t.Errorf("%s: got %d, want %d", tt.name, tt.got, tt.want)
		}
	}
}

// TestDisplayBlock_ZeroValue は DisplayBlock のゼロ値がデフォルトであることを確認する。
func TestDisplayBlock_ZeroValue(t *testing.T) {
	var b agent.DisplayBlock

	if b.Type != agent.BlockCommand {
		t.Errorf("Type zero value: got %d, want %d (BlockCommand)", b.Type, agent.BlockCommand)
	}
	if !b.CreatedAt.IsZero() {
		t.Errorf("CreatedAt zero value: got %v, want zero time", b.CreatedAt)
	}
	if b.Command != "" {
		t.Errorf("Command zero value: got %q, want empty", b.Command)
	}
	if b.Output != nil {
		t.Errorf("Output zero value: got %v, want nil", b.Output)
	}
	if b.ExitCode != 0 {
		t.Errorf("ExitCode zero value: got %d, want 0", b.ExitCode)
	}
	if b.Completed {
		t.Errorf("Completed zero value: got true, want false")
	}
	if b.Duration != 0 {
		t.Errorf("Duration zero value: got %v, want 0", b.Duration)
	}
	if b.Message != "" {
		t.Errorf("Message zero value: got %q, want empty", b.Message)
	}
	if b.UserText != "" {
		t.Errorf("UserText zero value: got %q, want empty", b.UserText)
	}
	if b.SystemMsg != "" {
		t.Errorf("SystemMsg zero value: got %q, want empty", b.SystemMsg)
	}
}

// TestNewCommandBlock はコマンドブロックのコンストラクタを検証する。
func TestNewCommandBlock(t *testing.T) {
	before := time.Now()
	b := agent.NewCommandBlock("nmap -sV 10.0.0.1")
	after := time.Now()

	if b.Type != agent.BlockCommand {
		t.Errorf("Type: got %d, want %d (BlockCommand)", b.Type, agent.BlockCommand)
	}
	if b.Command != "nmap -sV 10.0.0.1" {
		t.Errorf("Command: got %q, want %q", b.Command, "nmap -sV 10.0.0.1")
	}
	if b.CreatedAt.Before(before) || b.CreatedAt.After(after) {
		t.Errorf("CreatedAt: %v not between %v and %v", b.CreatedAt, before, after)
	}
	if b.Completed {
		t.Errorf("Completed: got true, want false (new command)")
	}
}

// TestNewThinkingBlock は思考ブロックのコンストラクタを検証する。
func TestNewThinkingBlock(t *testing.T) {
	before := time.Now()
	b := agent.NewThinkingBlock()
	after := time.Now()

	if b.Type != agent.BlockThinking {
		t.Errorf("Type: got %d, want %d (BlockThinking)", b.Type, agent.BlockThinking)
	}
	if b.CreatedAt.Before(before) || b.CreatedAt.After(after) {
		t.Errorf("CreatedAt: %v not between %v and %v", b.CreatedAt, before, after)
	}
	if b.ThinkingDone {
		t.Errorf("ThinkingDone: got true, want false (new thinking)")
	}
}

// TestNewAIMessageBlock は AI メッセージブロックのコンストラクタを検証する。
func TestNewAIMessageBlock(t *testing.T) {
	before := time.Now()
	b := agent.NewAIMessageBlock("I'll start by scanning the target.")
	after := time.Now()

	if b.Type != agent.BlockAIMessage {
		t.Errorf("Type: got %d, want %d (BlockAIMessage)", b.Type, agent.BlockAIMessage)
	}
	if b.Message != "I'll start by scanning the target." {
		t.Errorf("Message: got %q, want %q", b.Message, "I'll start by scanning the target.")
	}
	if b.CreatedAt.Before(before) || b.CreatedAt.After(after) {
		t.Errorf("CreatedAt: %v not between %v and %v", b.CreatedAt, before, after)
	}
}

// TestNewMemoryBlock はメモリブロックのコンストラクタを検証する。
func TestNewMemoryBlock(t *testing.T) {
	before := time.Now()
	b := agent.NewMemoryBlock("high", "Port 22 open (SSH)")
	after := time.Now()

	if b.Type != agent.BlockMemory {
		t.Errorf("Type: got %d, want %d (BlockMemory)", b.Type, agent.BlockMemory)
	}
	if b.Severity != "high" {
		t.Errorf("Severity: got %q, want %q", b.Severity, "high")
	}
	if b.Title != "Port 22 open (SSH)" {
		t.Errorf("Title: got %q, want %q", b.Title, "Port 22 open (SSH)")
	}
	if b.CreatedAt.Before(before) || b.CreatedAt.After(after) {
		t.Errorf("CreatedAt: %v not between %v and %v", b.CreatedAt, before, after)
	}
}

// TestNewSubTaskBlock はサブタスクブロックのコンストラクタを検証する。
func TestNewSubTaskBlock(t *testing.T) {
	before := time.Now()
	b := agent.NewSubTaskBlock("task-1", "Enumerate SMB shares")
	after := time.Now()

	if b.Type != agent.BlockSubTask {
		t.Errorf("Type: got %d, want %d (BlockSubTask)", b.Type, agent.BlockSubTask)
	}
	if b.TaskID != "task-1" {
		t.Errorf("TaskID: got %q, want %q", b.TaskID, "task-1")
	}
	if b.TaskGoal != "Enumerate SMB shares" {
		t.Errorf("TaskGoal: got %q, want %q", b.TaskGoal, "Enumerate SMB shares")
	}
	if b.CreatedAt.Before(before) || b.CreatedAt.After(after) {
		t.Errorf("CreatedAt: %v not between %v and %v", b.CreatedAt, before, after)
	}
	if b.TaskDone {
		t.Errorf("TaskDone: got true, want false (new subtask)")
	}
}

// TestNewUserInputBlock はユーザー入力ブロックのコンストラクタを検証する。
func TestNewUserInputBlock(t *testing.T) {
	before := time.Now()
	b := agent.NewUserInputBlock("scan the target please")
	after := time.Now()

	if b.Type != agent.BlockUserInput {
		t.Errorf("Type: got %d, want %d (BlockUserInput)", b.Type, agent.BlockUserInput)
	}
	if b.UserText != "scan the target please" {
		t.Errorf("UserText: got %q, want %q", b.UserText, "scan the target please")
	}
	if b.CreatedAt.Before(before) || b.CreatedAt.After(after) {
		t.Errorf("CreatedAt: %v not between %v and %v", b.CreatedAt, before, after)
	}
}

// TestNewSystemBlock はシステムブロックのコンストラクタを検証する。
func TestNewSystemBlock(t *testing.T) {
	before := time.Now()
	b := agent.NewSystemBlock("Agent started")
	after := time.Now()

	if b.Type != agent.BlockSystem {
		t.Errorf("Type: got %d, want %d (BlockSystem)", b.Type, agent.BlockSystem)
	}
	if b.SystemMsg != "Agent started" {
		t.Errorf("SystemMsg: got %q, want %q", b.SystemMsg, "Agent started")
	}
	if b.CreatedAt.Before(before) || b.CreatedAt.After(after) {
		t.Errorf("CreatedAt: %v not between %v and %v", b.CreatedAt, before, after)
	}
}
