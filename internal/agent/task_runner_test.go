package agent_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/0x6d61/pentecter/internal/agent"
)

func TestTaskRunner_Run_EchoCommand(t *testing.T) {
	runner := newTestRunner()
	events := make(chan agent.Event, 64)

	tr := agent.NewTaskRunner(runner, nil, events)

	task := agent.NewSubTask("task-1", agent.TaskKindRunner, "echo test")
	task.Command = "echo hello-runner"

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Run in goroutine (it blocks until done)
	go tr.Run(ctx, task)

	// Wait for task to complete
	select {
	case <-task.Done():
		// OK
	case <-time.After(4 * time.Second):
		t.Fatal("timeout waiting for task to complete")
	}

	// Verify status
	if task.Status != agent.TaskStatusCompleted {
		t.Errorf("Status: got %q, want %q", task.Status, agent.TaskStatusCompleted)
	}

	// Verify output contains the echo content
	output := task.FullOutput()
	if !strings.Contains(output, "hello-runner") {
		t.Errorf("FullOutput should contain 'hello-runner', got: %q", output)
	}

	// Verify EventSubTaskComplete was emitted
	gotComplete := false
	deadline := time.After(1 * time.Second)
	for {
		select {
		case e := <-events:
			if e.Type == agent.EventSubTaskComplete && e.TaskID == "task-1" {
				gotComplete = true
			}
		case <-deadline:
			goto done
		}
	}
done:
	if !gotComplete {
		t.Error("expected EventSubTaskComplete to be emitted")
	}
}

func TestTaskRunner_Run_EmptyCommand(t *testing.T) {
	runner := newTestRunner()
	events := make(chan agent.Event, 64)

	tr := agent.NewTaskRunner(runner, nil, events)

	task := agent.NewSubTask("task-2", agent.TaskKindRunner, "empty test")
	task.Command = ""

	ctx := context.Background()
	go tr.Run(ctx, task)

	// Wait for task to complete
	select {
	case <-task.Done():
		// OK
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for task to complete")
	}

	if task.Status != agent.TaskStatusFailed {
		t.Errorf("Status: got %q, want %q", task.Status, agent.TaskStatusFailed)
	}
	if task.Error == "" {
		t.Error("Error should be set for empty command")
	}
}

func TestTaskRunner_Run_ContextCancel(t *testing.T) {
	runner := newTestRunner()
	events := make(chan agent.Event, 64)

	tr := agent.NewTaskRunner(runner, nil, events)

	// Cancel the context before running — should cause immediate failure
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel

	task := agent.NewSubTask("task-3", agent.TaskKindRunner, "cancel test")
	task.Command = "echo should-not-run"

	go tr.Run(ctx, task)

	// Wait for task to complete
	select {
	case <-task.Done():
		// OK
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for cancelled task to complete")
	}

	// Status should be failed or cancelled (pre-cancelled context → command start fails)
	if task.Status != agent.TaskStatusFailed && task.Status != agent.TaskStatusCancelled {
		t.Errorf("Status: got %q, want failed or cancelled", task.Status)
	}
}
