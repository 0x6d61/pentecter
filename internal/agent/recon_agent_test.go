package agent_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/0x6d61/pentecter/internal/agent"
	"github.com/0x6d61/pentecter/pkg/schema"
)

func TestBuildReconPrompt_ContainsNmap(t *testing.T) {
	// buildReconPrompt is unexported, but we can test it indirectly
	// through SpawnReconAgent which uses it as the Command field.
	// For this test, we use a mock brain that captures the input.

	mb := &mockBrain{
		actions: []*schema.Action{
			{Thought: "done", Action: schema.ActionComplete},
		},
	}

	runner := newSmartTestRunner()
	events := make(chan agent.Event, 64)
	reconBrain := &mockBrain{
		actions: []*schema.Action{
			{Thought: "scanning", Action: schema.ActionRun, Command: "nmap -sV -sC -p- 10.0.0.5"},
			{Thought: "done", Action: schema.ActionComplete},
		},
	}

	// Create TaskManager with reconBrain
	tm := agent.NewTaskManager(runner, nil, events, mb, reconBrain)

	tree := agent.NewAttackDataTree("10.0.0.5", 2, 0)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	taskID, err := agent.SpawnReconAgent(ctx, agent.SpawnReconAgentConfig{
		TaskMgr:    tm,
		AttackData: tree,
		TargetHost: "10.0.0.5",
		TargetID:   1,
	})
	if err != nil {
		t.Fatalf("SpawnReconAgent failed: %v", err)
	}
	if taskID == "" {
		t.Fatal("SpawnReconAgent should return a non-empty taskID")
	}

	// Wait for task completion
	task, ok := tm.GetTask(taskID)
	if !ok {
		t.Fatal("Task not found after spawn")
	}

	select {
	case <-task.Done():
	case <-time.After(8 * time.Second):
		t.Fatal("timeout waiting for ReconAgent to complete")
	}

	// Verify the reconBrain received the prompt containing nmap instructions
	if len(reconBrain.inputs) == 0 {
		t.Fatal("reconBrain should have received at least one Think() call")
	}
	instruction := reconBrain.inputs[0].TaskInstruction
	if !strings.Contains(instruction, "nmap") {
		t.Errorf("ReconAgent prompt should contain 'nmap', got: %q", instruction[:min(len(instruction), 200)])
	}
}

func TestBuildReconPrompt_ContainsKnowledgeActions(t *testing.T) {
	reconBrain := &mockBrain{
		actions: []*schema.Action{
			{Thought: "done", Action: schema.ActionComplete},
		},
	}
	runner := newSmartTestRunner()
	events := make(chan agent.Event, 64)
	tm := agent.NewTaskManager(runner, nil, events, nil, reconBrain)
	tree := agent.NewAttackDataTree("10.0.0.5", 2, 0)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	taskID, err := agent.SpawnReconAgent(ctx, agent.SpawnReconAgentConfig{
		TaskMgr:    tm,
		AttackData: tree,
		TargetHost: "10.0.0.5",
		TargetID:   1,
	})
	if err != nil {
		t.Fatalf("SpawnReconAgent failed: %v", err)
	}

	task, _ := tm.GetTask(taskID)
	select {
	case <-task.Done():
	case <-time.After(8 * time.Second):
		t.Fatal("timeout")
	}

	instruction := reconBrain.inputs[0].TaskInstruction
	if !strings.Contains(instruction, "search_knowledge") {
		t.Error("ReconAgent prompt should contain 'search_knowledge'")
	}
	if !strings.Contains(instruction, "read_knowledge") {
		t.Error("ReconAgent prompt should contain 'read_knowledge'")
	}
}

func TestBuildReconPrompt_BlocksWebTools(t *testing.T) {
	reconBrain := &mockBrain{
		actions: []*schema.Action{
			{Thought: "done", Action: schema.ActionComplete},
		},
	}
	runner := newSmartTestRunner()
	events := make(chan agent.Event, 64)
	tm := agent.NewTaskManager(runner, nil, events, nil, reconBrain)
	tree := agent.NewAttackDataTree("10.0.0.5", 2, 0)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	taskID, err := agent.SpawnReconAgent(ctx, agent.SpawnReconAgentConfig{
		TaskMgr:    tm,
		AttackData: tree,
		TargetHost: "10.0.0.5",
		TargetID:   1,
	})
	if err != nil {
		t.Fatalf("SpawnReconAgent failed: %v", err)
	}

	task, _ := tm.GetTask(taskID)
	select {
	case <-task.Done():
	case <-time.After(8 * time.Second):
		t.Fatal("timeout")
	}

	instruction := reconBrain.inputs[0].TaskInstruction
	if !strings.Contains(instruction, "Do NOT") || !strings.Contains(instruction, "web") {
		t.Error("ReconAgent prompt should explicitly prohibit web reconnaissance tools")
	}
}

func TestSpawnReconAgent_Success(t *testing.T) {
	reconBrain := &mockBrain{
		actions: []*schema.Action{
			{Thought: "done", Action: schema.ActionComplete},
		},
	}
	runner := newSmartTestRunner()
	events := make(chan agent.Event, 64)
	tm := agent.NewTaskManager(runner, nil, events, nil, reconBrain)
	tree := agent.NewAttackDataTree("10.0.0.5", 2, 0)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	taskID, err := agent.SpawnReconAgent(ctx, agent.SpawnReconAgentConfig{
		TaskMgr:    tm,
		AttackData: tree,
		TargetHost: "10.0.0.5",
		TargetID:   1,
	})
	if err != nil {
		t.Fatalf("SpawnReconAgent should succeed: %v", err)
	}
	if !strings.HasPrefix(taskID, "task-") {
		t.Errorf("taskID should start with 'task-', got: %q", taskID)
	}

	// Wait for completion
	task, ok := tm.GetTask(taskID)
	if !ok {
		t.Fatal("Task should exist")
	}
	select {
	case <-task.Done():
	case <-time.After(8 * time.Second):
		t.Fatal("timeout")
	}

	if task.Status != agent.TaskStatusCompleted {
		t.Errorf("Task should be completed, got: %q", task.Status)
	}
}

func TestSpawnReconAgent_NoBrain(t *testing.T) {
	runner := newSmartTestRunner()
	events := make(chan agent.Event, 64)
	// reconBrain = nil
	tm := agent.NewTaskManager(runner, nil, events, nil, nil)
	tree := agent.NewAttackDataTree("10.0.0.5", 2, 0)

	ctx := context.Background()
	_, err := agent.SpawnReconAgent(ctx, agent.SpawnReconAgentConfig{
		TaskMgr:    tm,
		AttackData: tree,
		TargetHost: "10.0.0.5",
		TargetID:   1,
	})
	if err == nil {
		t.Fatal("SpawnReconAgent should fail when reconBrain is nil")
	}
	if !strings.Contains(err.Error(), "ReconBrain") {
		t.Errorf("Error should mention ReconBrain, got: %q", err.Error())
	}
}

func TestSpawnReconAgent_NilTaskMgr(t *testing.T) {
	ctx := context.Background()
	_, err := agent.SpawnReconAgent(ctx, agent.SpawnReconAgentConfig{
		TaskMgr:    nil,
		TargetHost: "10.0.0.5",
	})
	if err == nil {
		t.Fatal("SpawnReconAgent should fail when TaskMgr is nil")
	}
	if !strings.Contains(err.Error(), "TaskManager") {
		t.Errorf("Error should mention TaskManager, got: %q", err.Error())
	}
}
