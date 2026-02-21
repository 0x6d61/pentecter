package agent_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/0x6d61/pentecter/internal/agent"
	"github.com/0x6d61/pentecter/internal/tools"
	"github.com/0x6d61/pentecter/pkg/schema"
)

// TestHandleKillTask_NoTaskManager tests kill_task with nil taskMgr returns error.
func TestHandleKillTask_NoTaskManager(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	mb := &mockBrain{
		actions: []*schema.Action{
			{Thought: "killing task", Action: schema.ActionKillTask, TaskID: "task-1"},
		},
	}
	loop, events, _, _ := newTestLoop(target, mb)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go loop.Run(ctx)
	deadline := time.After(4 * time.Second)
	for {
		select {
		case e := <-events:
			if e.Type == agent.EventComplete {
				if len(mb.inputs) < 2 {
					t.Fatalf("expected at least 2 Think() calls, got %d", len(mb.inputs))
				}
				toolOutput := mb.inputs[1].ToolOutput
				if !strings.Contains(toolOutput, "Error") {
					t.Errorf("should contain Error, got: %s", toolOutput)
				}
				if !strings.Contains(toolOutput, "TaskManager not configured") {
					t.Errorf("should mention TaskManager, got: %s", toolOutput)
				}
				return
			}
		case <-deadline:
			t.Fatal("timeout waiting for EventComplete")
		}
	}
}

// TestHandleKillTask_TaskNotFound tests kill_task with nonexistent TaskID.
func TestHandleKillTask_TaskNotFound(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	mb := &mockBrain{
		actions: []*schema.Action{
			{Thought: "killing nonexistent", Action: schema.ActionKillTask, TaskID: "task-999"},
		},
	}
	loop, _, events, _, _ := newTestLoopWithTaskManager(target, mb)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go loop.Run(ctx)
	deadline := time.After(4 * time.Second)
	for {
		select {
		case e := <-events:
			if e.Type == agent.EventComplete {
				if len(mb.inputs) < 2 {
					t.Fatalf("expected at least 2 Think() calls, got %d", len(mb.inputs))
				}
				toolOutput := mb.inputs[1].ToolOutput
				if !strings.Contains(toolOutput, "Error") {
					t.Errorf("should contain Error, got: %s", toolOutput)
				}
				if !strings.Contains(toolOutput, "not found") {
					t.Errorf("should mention not found, got: %s", toolOutput)
				}
				return
			}
		case <-deadline:
			t.Fatal("timeout waiting for EventComplete")
		}
	}
}

// TestBuildTaskResult_WithFindings tests that Findings appear in result text.
func TestBuildTaskResult_WithFindings(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	mb := &mockBrain{
		actions: []*schema.Action{
			{Thought: "waiting", Action: schema.ActionWait, TaskID: "task-inject-1"},
		},
	}
	loop, taskMgr, events, _, _ := newTestLoopWithTaskManager(target, mb)
	task := agent.NewSubTask("task-inject-1", agent.TaskKindSmart, "find vulns")
	task.Findings = []string{
		"SQL injection in /api/users",
		"XSS in /search",
	}
	task.Status = agent.TaskStatusCompleted
	task.Complete()
	taskMgr.InjectTask("task-inject-1", task)
	taskMgr.InjectDone("task-inject-1")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go loop.Run(ctx)
	deadline := time.After(8 * time.Second)
	for {
		select {
		case e := <-events:
			if e.Type == agent.EventComplete {
				if len(mb.inputs) < 2 {
					t.Fatalf("expected at least 2 Think() calls, got %d", len(mb.inputs))
				}
				toolOutput := mb.inputs[1].ToolOutput
				if !strings.Contains(toolOutput, "findings") {
					t.Errorf("should contain findings, got: %s", toolOutput)
				}
				if !strings.Contains(toolOutput, "SQL injection") {
					t.Errorf("should contain SQL injection, got: %s", toolOutput)
				}
				if !strings.Contains(toolOutput, "XSS") {
					t.Errorf("should contain XSS, got: %s", toolOutput)
				}
				return
			}
		case <-deadline:
			t.Fatal("timeout waiting for EventComplete")
		}
	}
}

// TestBuildTaskResult_LongOutput tests that >2000 char output is truncated.
func TestBuildTaskResult_LongOutput(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	mb := &mockBrain{
		actions: []*schema.Action{
			{Thought: "waiting", Action: schema.ActionWait, TaskID: "task-inject-2"},
		},
	}
	loop, taskMgr, events, _, _ := newTestLoopWithTaskManager(target, mb)
	task := agent.NewSubTask("task-inject-2", agent.TaskKindSmart, "generate output")
	longLine := strings.Repeat("A", 3000)
	task.AppendOutput(longLine)
	task.Status = agent.TaskStatusCompleted
	task.Complete()
	taskMgr.InjectTask("task-inject-2", task)
	taskMgr.InjectDone("task-inject-2")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go loop.Run(ctx)
	deadline := time.After(8 * time.Second)
	for {
		select {
		case e := <-events:
			if e.Type == agent.EventComplete {
				if len(mb.inputs) < 2 {
					t.Fatalf("expected at least 2 Think() calls, got %d", len(mb.inputs))
				}
				toolOutput := mb.inputs[1].ToolOutput
				if !strings.Contains(toolOutput, "truncated") {
					preview := toolOutput
					if len(preview) > 200 {
						preview = preview[:200]
					}
					t.Errorf("should contain truncated, got (len=%d): %s", len(toolOutput), preview)
				}
				return
			}
		case <-deadline:
			t.Fatal("timeout waiting for EventComplete")
		}
	}
}

// TestBuildTaskResult_WithEntities tests SubTask Entities are added to Target.
func TestBuildTaskResult_WithEntities(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	mb := &mockBrain{
		actions: []*schema.Action{
			{Thought: "waiting", Action: schema.ActionWait, TaskID: "task-inject-3"},
		},
	}
	loop, taskMgr, events, _, _ := newTestLoopWithTaskManager(target, mb)
	task := agent.NewSubTask("task-inject-3", agent.TaskKindSmart, "discover entities")
	task.Entities = []tools.Entity{
		{Type: tools.EntityPort, Value: "8080", Context: "open port"},
		{Type: tools.EntityCVE, Value: "CVE-2023-12345", Context: "vulnerability found"},
	}
	task.Status = agent.TaskStatusCompleted
	task.Complete()
	taskMgr.InjectTask("task-inject-3", task)
	taskMgr.InjectDone("task-inject-3")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go loop.Run(ctx)
	deadline := time.After(8 * time.Second)
	for {
		select {
		case e := <-events:
			if e.Type == agent.EventComplete {
				entities := target.SnapshotEntities()
				found8080 := false
				foundCVE := false
				for _, ent := range entities {
					if ent.Type == tools.EntityPort && ent.Value == "8080" {
						found8080 = true
					}
					if ent.Type == tools.EntityCVE && ent.Value == "CVE-2023-12345" {
						foundCVE = true
					}
				}
				if !found8080 {
					t.Errorf("expected Entity port:8080, entities: %v", entities)
				}
				if !foundCVE {
					t.Errorf("expected Entity cve:CVE-2023-12345, entities: %v", entities)
				}
				return
			}
		case <-deadline:
			t.Fatal("timeout waiting for EventComplete")
		}
	}
}

// TestBuildTaskResult_EmptyOutput tests empty task has no findings/truncated.
func TestBuildTaskResult_EmptyOutput(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	mb := &mockBrain{
		actions: []*schema.Action{
			{Thought: "waiting", Action: schema.ActionWait, TaskID: "task-inject-4"},
		},
	}
	loop, taskMgr, events, _, _ := newTestLoopWithTaskManager(target, mb)
	task := agent.NewSubTask("task-inject-4", agent.TaskKindSmart, "no output task")
	task.Status = agent.TaskStatusCompleted
	task.Complete()
	taskMgr.InjectTask("task-inject-4", task)
	taskMgr.InjectDone("task-inject-4")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go loop.Run(ctx)
	deadline := time.After(8 * time.Second)
	for {
		select {
		case e := <-events:
			if e.Type == agent.EventComplete {
				if len(mb.inputs) < 2 {
					t.Fatalf("expected at least 2 Think() calls, got %d", len(mb.inputs))
				}
				toolOutput := mb.inputs[1].ToolOutput
				if strings.Contains(toolOutput, "findings") {
					t.Errorf("should not contain findings, got: %s", toolOutput)
				}
				if strings.Contains(toolOutput, "truncated") {
					t.Errorf("should not contain truncated, got: %s", toolOutput)
				}
				if !strings.Contains(toolOutput, "no output task") {
					t.Errorf("should contain goal text, got: %s", toolOutput)
				}
				return
			}
		case <-deadline:
			t.Fatal("timeout waiting for EventComplete")
		}
	}
}

// TestHandleWait_NoTaskManager tests wait with nil taskMgr returns error.
func TestHandleWait_NoTaskManager(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	mb := &mockBrain{
		actions: []*schema.Action{
			{Thought: "waiting", Action: schema.ActionWait},
		},
	}
	loop, events, _, _ := newTestLoop(target, mb)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go loop.Run(ctx)
	deadline := time.After(4 * time.Second)
	for {
		select {
		case e := <-events:
			if e.Type == agent.EventComplete {
				if len(mb.inputs) < 2 {
					t.Fatalf("expected at least 2 Think() calls, got %d", len(mb.inputs))
				}
				toolOutput := mb.inputs[1].ToolOutput
				if !strings.Contains(toolOutput, "Error") {
					t.Errorf("should contain Error, got: %s", toolOutput)
				}
				if !strings.Contains(toolOutput, "TaskManager not configured") {
					t.Errorf("should mention TaskManager, got: %s", toolOutput)
				}
				return
			}
		case <-deadline:
			t.Fatal("timeout waiting for EventComplete")
		}
	}
}

// TestHandleWait_SpecificTask tests waiting for a specific task ID.
func TestHandleWait_SpecificTask(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	mb := &mockBrain{
		actions: []*schema.Action{
			{Thought: "waiting for injected", Action: schema.ActionWait, TaskID: "task-inject-5"},
		},
	}
	loop, taskMgr, events, _, _ := newTestLoopWithTaskManager(target, mb)
	task := agent.NewSubTask("task-inject-5", agent.TaskKindSmart, "specific task")
	task.AppendOutput("hello from specific task")
	task.Status = agent.TaskStatusCompleted
	task.Complete()
	taskMgr.InjectTask("task-inject-5", task)
	taskMgr.InjectDone("task-inject-5")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go loop.Run(ctx)
	deadline := time.After(8 * time.Second)
	for {
		select {
		case e := <-events:
			if e.Type == agent.EventComplete {
				if len(mb.inputs) < 2 {
					t.Fatalf("expected at least 2 Think() calls, got %d", len(mb.inputs))
				}
				toolOutput := mb.inputs[1].ToolOutput
				if !strings.Contains(toolOutput, "specific task") {
					t.Errorf("should contain goal text, got: %s", toolOutput)
				}
				if !strings.Contains(toolOutput, "hello from specific task") {
					t.Errorf("should contain task output, got: %s", toolOutput)
				}
				return
			}
		case <-deadline:
			t.Fatal("timeout waiting for EventComplete")
		}
	}
}

// TestHandleWait_ContextCancelled tests context cancellation stops the wait.
func TestHandleWait_ContextCancelled(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	mb := &mockBrain{
		actions: []*schema.Action{
			{Thought: "spawning", Action: schema.ActionSpawnTask,
				Command: "sleep 60", TaskGoal: "long task"},
			{Thought: "waiting forever", Action: schema.ActionWait, TaskID: "task-1"},
		},
	}
	loop, _, events, _, _ := newTestLoopWithTaskManager(target, mb)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go loop.Run(ctx)
	deadline := time.After(5 * time.Second)
	for {
		select {
		case e := <-events:
			if e.Type == agent.EventLog && strings.Contains(e.Message, "Agent stopped") {
				return
			}
		case <-deadline:
			if ctx.Err() != nil {
				return
			}
			t.Fatal("timeout: loop did not stop after context cancellation")
		}
	}
}

// TestDrainCompletedTasks_NoTaskManager tests drain with nil taskMgr.
func TestDrainCompletedTasks_NoTaskManager(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	mb := &mockBrain{
		actions: []*schema.Action{
			{Thought: "echo test", Action: schema.ActionRun, Command: "echo hello"},
		},
	}
	loop, events, _, _ := newTestLoop(target, mb)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go loop.Run(ctx)
	deadline := time.After(4 * time.Second)
	for {
		select {
		case e := <-events:
			if e.Type == agent.EventComplete {
				return
			}
		case <-deadline:
			t.Fatal("timeout waiting for EventComplete")
		}
	}
}

// TestDrainCompletedTasks_PushModel tests auto-injection of completed subtask results.
func TestDrainCompletedTasks_PushModel(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	mb := &mockBrain{
		actions: []*schema.Action{
			{Thought: "checking", Action: schema.ActionThink},
		},
	}
	loop, taskMgr, events, _, _ := newTestLoopWithTaskManager(target, mb)
	task := agent.NewSubTask("task-drain-1", agent.TaskKindSmart, "auto drain task")
	task.Findings = []string{"push model finding"}
	task.Status = agent.TaskStatusCompleted
	task.Complete()
	taskMgr.InjectTask("task-drain-1", task)
	taskMgr.InjectDone("task-drain-1")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go loop.Run(ctx)
	deadline := time.After(8 * time.Second)
	for {
		select {
		case e := <-events:
			if e.Type == agent.EventComplete {
				foundDrainResult := false
				for _, input := range mb.inputs {
					if strings.Contains(input.ToolOutput, "SubTask Completed") &&
						strings.Contains(input.ToolOutput, "push model finding") {
						foundDrainResult = true
						break
					}
				}
				if !foundDrainResult {
					t.Errorf("expected drained subtask result in Think() ToolOutput")
				}
				return
			}
		case <-deadline:
			t.Fatal("timeout waiting for EventComplete")
		}
	}
}

// TestBuildTaskResult_WebReconUpdatesReconTree tests that completing a web_recon
// subtask calls CompleteAllPortTasks on the ReconTree.
func TestBuildTaskResult_WebReconUpdatesReconTree(t *testing.T) {
	target := agent.NewTarget(1, "10.0.0.1")
	mb := &mockBrain{
		actions: []*schema.Action{
			{Thought: "waiting", Action: schema.ActionWait, TaskID: "task-inject-recon"},
		},
	}
	loop, taskMgr, events, _, _ := newTestLoopWithTaskManager(target, mb)

	// ReconTree をセットアップ
	tree := agent.NewReconTree("10.0.0.1", 2)
	tree.AddPort(80, "http", "Apache")
	// SubAgent 単位で InProgress にマーク（SpawnWebReconForPort の実際の動作を再現）
	// AddPort(http) は EndpointEnum + VhostDiscov を Pending にする
	node := tree.Ports[0]
	for _, tt := range []agent.ReconTaskType{agent.TaskEndpointEnum, agent.TaskVhostDiscov} {
		node.SetReconStatusForTest(tt, agent.StatusInProgress)
	}
	tree.SetActiveForTest(1) // SubAgent 1つ分
	loop.WithReconTree(tree)

	// web_recon phase の SubTask を注入
	task := agent.NewSubTask("task-inject-recon", agent.TaskKindSmart, "web recon on :80")
	task.Metadata = agent.TaskMetadata{
		Port:    80,
		Service: "http",
		Phase:   "web_recon",
	}
	task.Status = agent.TaskStatusCompleted
	task.Complete()
	taskMgr.InjectTask("task-inject-recon", task)
	taskMgr.InjectDone("task-inject-recon")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go loop.Run(ctx)
	deadline := time.After(8 * time.Second)
	for {
		select {
		case e := <-events:
			if e.Type == agent.EventComplete {
				// CompleteAllPortTasks により InProgress だった2タスクが Complete になっていること
				if got := tree.CountComplete(); got != 2 {
					t.Errorf("CountComplete = %d, want 2 after web_recon complete", got)
				}
				// Pending が 0 であること
				if got := tree.CountPending(); got != 0 {
					t.Errorf("CountPending = %d, want 0 after web_recon complete", got)
				}
				// IsLocked が false（全タスク完了で自動解除）
				if tree.IsLocked() {
					t.Error("ReconTree should be auto-unlocked after all tasks complete")
				}
				return
			}
		case <-deadline:
			t.Fatal("timeout waiting for EventComplete")
		}
	}
}
