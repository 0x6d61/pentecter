package agent_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/0x6d61/pentecter/internal/agent"
	"github.com/0x6d61/pentecter/pkg/schema"
)

func TestTaskManager_SpawnTask_Runner(t *testing.T) {
	runner := newTestRunner()
	events := make(chan agent.Event, 64)

	tm := agent.NewTaskManager(runner, nil, events, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	taskID, err := tm.SpawnTask(ctx, agent.SpawnTaskRequest{
		Kind:    agent.TaskKindRunner,
		Goal:    "echo test",
		Command: "echo hello-manager",
	})
	if err != nil {
		t.Fatalf("SpawnTask: %v", err)
	}
	if taskID == "" {
		t.Fatal("SpawnTask returned empty taskID")
	}

	// WaitAny should return this taskID when it completes
	completedID := tm.WaitAny(ctx)
	if completedID != taskID {
		t.Errorf("WaitAny: got %q, want %q", completedID, taskID)
	}

	// Verify the task is completed
	task, ok := tm.GetTask(taskID)
	if !ok {
		t.Fatal("GetTask: task not found")
	}
	if task.Status != agent.TaskStatusCompleted {
		t.Errorf("Status: got %q, want %q", task.Status, agent.TaskStatusCompleted)
	}
}

func TestTaskManager_WaitTask(t *testing.T) {
	runner := newTestRunner()
	events := make(chan agent.Event, 64)

	tm := agent.NewTaskManager(runner, nil, events, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	taskID, err := tm.SpawnTask(ctx, agent.SpawnTaskRequest{
		Kind:    agent.TaskKindRunner,
		Goal:    "wait test",
		Command: "echo wait-test",
	})
	if err != nil {
		t.Fatalf("SpawnTask: %v", err)
	}

	done := tm.WaitTask(ctx, taskID)
	if !done {
		t.Error("WaitTask should return true when task completes")
	}

	task, _ := tm.GetTask(taskID)
	if task.Status != agent.TaskStatusCompleted {
		t.Errorf("Status: got %q, want %q", task.Status, agent.TaskStatusCompleted)
	}
}

func TestTaskManager_GetTask(t *testing.T) {
	runner := newTestRunner()
	events := make(chan agent.Event, 64)

	tm := agent.NewTaskManager(runner, nil, events, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	taskID, err := tm.SpawnTask(ctx, agent.SpawnTaskRequest{
		Kind:    agent.TaskKindRunner,
		Goal:    "get test",
		Command: "echo get-test",
	})
	if err != nil {
		t.Fatalf("SpawnTask: %v", err)
	}

	task, ok := tm.GetTask(taskID)
	if !ok {
		t.Fatal("GetTask: task not found")
	}
	if task.ID != taskID {
		t.Errorf("ID: got %q, want %q", task.ID, taskID)
	}
	if task.Goal != "get test" {
		t.Errorf("Goal: got %q, want %q", task.Goal, "get test")
	}

	// Non-existent task
	_, ok = tm.GetTask("nonexistent")
	if ok {
		t.Error("GetTask should return false for nonexistent task")
	}
}

func TestTaskManager_KillTask(t *testing.T) {
	runner := newTestRunner()
	events := make(chan agent.Event, 64)

	tm := agent.NewTaskManager(runner, nil, events, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Spawn a slow task — use a pre-cancelled context approach
	// We spawn with a valid context, then kill it
	taskID, err := tm.SpawnTask(ctx, agent.SpawnTaskRequest{
		Kind:    agent.TaskKindRunner,
		Goal:    "kill test",
		Command: "echo killed",
	})
	if err != nil {
		t.Fatalf("SpawnTask: %v", err)
	}

	// Wait for task to finish (it's a fast echo)
	tm.WaitTask(ctx, taskID)

	// KillTask on an already-completed task should not return error
	err = tm.KillTask(taskID)
	if err != nil {
		t.Errorf("KillTask on completed task: %v", err)
	}

	// KillTask on nonexistent task
	err = tm.KillTask("nonexistent")
	if err == nil {
		t.Error("KillTask should return error for nonexistent task")
	}
}

func TestTaskManager_ActiveTasks(t *testing.T) {
	runner := newTestRunner()
	events := make(chan agent.Event, 64)

	tm := agent.NewTaskManager(runner, nil, events, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Spawn 2 tasks for target 1
	id1, _ := tm.SpawnTask(ctx, agent.SpawnTaskRequest{
		Kind:     agent.TaskKindRunner,
		Goal:     "task 1",
		Command:  "echo task1",
		TargetID: 1,
	})
	id2, _ := tm.SpawnTask(ctx, agent.SpawnTaskRequest{
		Kind:     agent.TaskKindRunner,
		Goal:     "task 2",
		Command:  "echo task2",
		TargetID: 1,
	})

	// Spawn 1 task for target 2
	_, _ = tm.SpawnTask(ctx, agent.SpawnTaskRequest{
		Kind:     agent.TaskKindRunner,
		Goal:     "task 3",
		Command:  "echo task3",
		TargetID: 2,
	})

	// Wait for all tasks to complete
	tm.WaitTask(ctx, id1)
	tm.WaitTask(ctx, id2)

	// AllTasks for target 1 should have 2
	allTarget1 := tm.AllTasks(1)
	if len(allTarget1) != 2 {
		t.Errorf("AllTasks(1): got %d, want 2", len(allTarget1))
	}

	// AllTasks for target 2 should have 1
	allTarget2 := tm.AllTasks(2)
	if len(allTarget2) != 1 {
		t.Errorf("AllTasks(2): got %d, want 1", len(allTarget2))
	}
}

func TestTaskManager_WaitAny_MultipleCompleted(t *testing.T) {
	runner := newTestRunner()
	events := make(chan agent.Event, 64)

	tm := agent.NewTaskManager(runner, nil, events, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	id1, _ := tm.SpawnTask(ctx, agent.SpawnTaskRequest{
		Kind:    agent.TaskKindRunner,
		Goal:    "multi 1",
		Command: "echo multi1",
	})
	id2, _ := tm.SpawnTask(ctx, agent.SpawnTaskRequest{
		Kind:    agent.TaskKindRunner,
		Goal:    "multi 2",
		Command: "echo multi2",
	})

	// Collect both completed IDs via WaitAny
	completed := make(map[string]bool)
	first := tm.WaitAny(ctx)
	completed[first] = true

	second := tm.WaitAny(ctx)
	completed[second] = true

	if !completed[id1] {
		t.Errorf("WaitAny should eventually return %q", id1)
	}
	if !completed[id2] {
		t.Errorf("WaitAny should eventually return %q", id2)
	}
}

func TestTaskManager_SpawnTask_Smart(t *testing.T) {
	// mockBrain: run "echo smart-task" → complete
	mb := &mockBrain{
		actions: []*schema.Action{
			{
				Thought: "executing smart task",
				Action:  schema.ActionRun,
				Command: "echo smart-task",
			},
			{
				Thought: "task done",
				Action:  schema.ActionComplete,
			},
		},
	}

	runner := newSmartTestRunner()
	events := make(chan agent.Event, 64)

	tm := agent.NewTaskManager(runner, nil, events, mb)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	taskID, err := tm.SpawnTask(ctx, agent.SpawnTaskRequest{
		Kind:       agent.TaskKindSmart,
		Goal:       "test smart",
		TargetHost: "10.0.0.5",
		MaxTurns:   10,
	})
	if err != nil {
		t.Fatalf("SpawnTask (smart): %v", err)
	}
	if taskID == "" {
		t.Fatal("SpawnTask returned empty taskID")
	}

	// WaitTask で完了を待つ
	done := tm.WaitTask(ctx, taskID)
	if !done {
		t.Fatal("WaitTask should return true when smart task completes")
	}

	// タスクの状態を検証
	task, ok := tm.GetTask(taskID)
	if !ok {
		t.Fatal("GetTask: task not found")
	}
	if task.Status != agent.TaskStatusCompleted {
		t.Errorf("Status: got %q, want %q", task.Status, agent.TaskStatusCompleted)
	}

	// 出力に "smart-task" が含まれること
	output := task.FullOutput()
	if !strings.Contains(output, "smart-task") {
		t.Errorf("FullOutput should contain 'smart-task', got: %q", output)
	}
}

func TestTaskManager_SpawnTask_Smart_NoBrain(t *testing.T) {
	runner := newSmartTestRunner()
	events := make(chan agent.Event, 64)

	// subBrain を nil にして作成
	tm := agent.NewTaskManager(runner, nil, events, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := tm.SpawnTask(ctx, agent.SpawnTaskRequest{
		Kind:       agent.TaskKindSmart,
		Goal:       "should fail",
		TargetHost: "10.0.0.5",
	})
	if err == nil {
		t.Fatal("SpawnTask (smart) should return error when subBrain is nil")
	}
	if !strings.Contains(err.Error(), "sub-brain") {
		t.Errorf("Error should mention sub-brain, got: %q", err.Error())
	}
}
