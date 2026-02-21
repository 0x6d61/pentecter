package agent_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/0x6d61/pentecter/internal/agent"
	"github.com/0x6d61/pentecter/pkg/schema"
)

func TestTaskManager_SpawnTask_Smart_Basic(t *testing.T) {
	mb := &mockBrain{
		actions: []*schema.Action{
			{Thought: "executing", Action: schema.ActionRun, Command: "echo hello-manager"},
			{Thought: "done", Action: schema.ActionComplete},
		},
	}

	runner := newSmartTestRunner()
	events := make(chan agent.Event, 64)

	tm := agent.NewTaskManager(runner, nil, events, mb)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	taskID, err := tm.SpawnTask(ctx, agent.SpawnTaskRequest{
		Kind:       agent.TaskKindSmart,
		Goal:       "echo test",
		Command:    "echo hello-manager",
		TargetHost: "10.0.0.5",
		MaxTurns:   10,
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
	mb := &mockBrain{
		actions: []*schema.Action{
			{Thought: "executing", Action: schema.ActionRun, Command: "echo wait-test"},
			{Thought: "done", Action: schema.ActionComplete},
		},
	}

	runner := newSmartTestRunner()
	events := make(chan agent.Event, 64)

	tm := agent.NewTaskManager(runner, nil, events, mb)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	taskID, err := tm.SpawnTask(ctx, agent.SpawnTaskRequest{
		Kind:       agent.TaskKindSmart,
		Goal:       "wait test",
		Command:    "echo wait-test",
		TargetHost: "10.0.0.5",
		MaxTurns:   10,
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
	mb := &mockBrain{
		actions: []*schema.Action{
			{Thought: "executing", Action: schema.ActionRun, Command: "echo get-test"},
			{Thought: "done", Action: schema.ActionComplete},
		},
	}

	runner := newSmartTestRunner()
	events := make(chan agent.Event, 64)

	tm := agent.NewTaskManager(runner, nil, events, mb)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	taskID, err := tm.SpawnTask(ctx, agent.SpawnTaskRequest{
		Kind:       agent.TaskKindSmart,
		Goal:       "get test",
		Command:    "echo get-test",
		TargetHost: "10.0.0.5",
		MaxTurns:   10,
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
	mb := &mockBrain{
		actions: []*schema.Action{
			{Thought: "executing", Action: schema.ActionRun, Command: "echo killed"},
			{Thought: "done", Action: schema.ActionComplete},
		},
	}

	runner := newSmartTestRunner()
	events := make(chan agent.Event, 64)

	tm := agent.NewTaskManager(runner, nil, events, mb)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	taskID, err := tm.SpawnTask(ctx, agent.SpawnTaskRequest{
		Kind:       agent.TaskKindSmart,
		Goal:       "kill test",
		Command:    "echo killed",
		TargetHost: "10.0.0.5",
		MaxTurns:   10,
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
	mb := &mockBrain{
		actions: []*schema.Action{
			{Thought: "executing", Action: schema.ActionRun, Command: "echo task-output"},
			{Thought: "done", Action: schema.ActionComplete},
		},
	}

	runner := newSmartTestRunner()
	events := make(chan agent.Event, 64)

	tm := agent.NewTaskManager(runner, nil, events, mb)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Spawn 2 tasks for target 1
	id1, _ := tm.SpawnTask(ctx, agent.SpawnTaskRequest{
		Kind:       agent.TaskKindSmart,
		Goal:       "task 1",
		Command:    "echo task1",
		TargetHost: "10.0.0.5",
		TargetID:   1,
		MaxTurns:   10,
	})
	id2, _ := tm.SpawnTask(ctx, agent.SpawnTaskRequest{
		Kind:       agent.TaskKindSmart,
		Goal:       "task 2",
		Command:    "echo task2",
		TargetHost: "10.0.0.5",
		TargetID:   1,
		MaxTurns:   10,
	})

	// Spawn 1 task for target 2
	_, _ = tm.SpawnTask(ctx, agent.SpawnTaskRequest{
		Kind:       agent.TaskKindSmart,
		Goal:       "task 3",
		Command:    "echo task3",
		TargetHost: "10.0.0.5",
		TargetID:   2,
		MaxTurns:   10,
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
	mb := &mockBrain{
		actions: []*schema.Action{
			{Thought: "executing", Action: schema.ActionRun, Command: "echo multi-output"},
			{Thought: "done", Action: schema.ActionComplete},
		},
	}

	runner := newSmartTestRunner()
	events := make(chan agent.Event, 64)

	tm := agent.NewTaskManager(runner, nil, events, mb)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	id1, _ := tm.SpawnTask(ctx, agent.SpawnTaskRequest{
		Kind:       agent.TaskKindSmart,
		Goal:       "multi 1",
		Command:    "echo multi1",
		TargetHost: "10.0.0.5",
		MaxTurns:   10,
	})
	id2, _ := tm.SpawnTask(ctx, agent.SpawnTaskRequest{
		Kind:       agent.TaskKindSmart,
		Goal:       "multi 2",
		Command:    "echo multi2",
		TargetHost: "10.0.0.5",
		MaxTurns:   10,
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
	// mockBrain: run "echo smart-task" -> complete
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

func TestTaskManager_DrainCompleted(t *testing.T) {
	// SmartSubAgent タスクを spawn -> 完了 -> DrainCompleted() で取得 -> 2回目は空
	mb := &mockBrain{
		actions: []*schema.Action{
			{Thought: "running", Action: schema.ActionRun, Command: "echo drain-test"},
			{Thought: "done", Action: schema.ActionComplete},
		},
	}

	runner := newSmartTestRunner()
	events := make(chan agent.Event, 64)

	tm := agent.NewTaskManager(runner, nil, events, mb)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	taskID, err := tm.SpawnTask(ctx, agent.SpawnTaskRequest{
		Kind:       agent.TaskKindSmart,
		Goal:       "test drain",
		TargetHost: "10.0.0.5",
		MaxTurns:   10,
	})
	if err != nil {
		t.Fatalf("SpawnTask: %v", err)
	}

	// タスク完了を待つ
	done := tm.WaitTask(ctx, taskID)
	if !done {
		t.Fatal("WaitTask should return true")
	}

	// WaitTask は task.Done() で待つため、goroutine が doneCh に送信するまで少し待つ
	time.Sleep(100 * time.Millisecond)

	// DrainCompleted で取得できること
	completed := tm.DrainCompleted()
	if len(completed) != 1 {
		t.Fatalf("DrainCompleted: got %d, want 1", len(completed))
	}
	if completed[0].ID != taskID {
		t.Errorf("DrainCompleted[0].ID: got %q, want %q", completed[0].ID, taskID)
	}

	// 2回目は空であること
	completed2 := tm.DrainCompleted()
	if len(completed2) != 0 {
		t.Errorf("DrainCompleted (2nd call): got %d, want 0", len(completed2))
	}
}

func TestTaskManager_DrainCompleted_Empty(t *testing.T) {
	// タスクなしで DrainCompleted() -> nil
	runner := newSmartTestRunner()
	events := make(chan agent.Event, 64)

	tm := agent.NewTaskManager(runner, nil, events, nil)

	completed := tm.DrainCompleted()
	if completed != nil {
		t.Errorf("DrainCompleted (no tasks): got %v, want nil", completed)
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

// --- ActiveTasks / DoneCh テスト ---

func TestTaskManager_ActiveTasks_Empty(t *testing.T) {
	// タスクが存在しない場合は nil/empty を返すこと
	runner := newSmartTestRunner()
	events := make(chan agent.Event, 64)

	tm := agent.NewTaskManager(runner, nil, events, nil)

	active := tm.ActiveTasks(1)
	if len(active) != 0 {
		t.Errorf("ActiveTasks on empty manager: got %d, want 0", len(active))
	}
}

func TestTaskManager_ActiveTasks_FiltersByTarget(t *testing.T) {
	// InjectTask を使って直接タスクを注入し、TargetID でフィルタリングされることを確認
	runner := newSmartTestRunner()
	events := make(chan agent.Event, 64)

	tm := agent.NewTaskManager(runner, nil, events, nil)

	// Target 1 の pending タスク
	task1 := agent.NewSubTask("task-inject-1", agent.TaskKindSmart, "scan ports")
	task1.TargetID = 1
	task1.Status = agent.TaskStatusPending
	tm.InjectTask("task-inject-1", task1)

	// Target 1 の running タスク
	task2 := agent.NewSubTask("task-inject-2", agent.TaskKindSmart, "enumerate services")
	task2.TargetID = 1
	task2.Status = agent.TaskStatusRunning
	tm.InjectTask("task-inject-2", task2)

	// Target 1 の completed タスク（active には含まれないはず）
	task3 := agent.NewSubTask("task-inject-3", agent.TaskKindSmart, "exploit vuln")
	task3.TargetID = 1
	task3.Status = agent.TaskStatusCompleted
	tm.InjectTask("task-inject-3", task3)

	// Target 2 の pending タスク（Target 1 の結果に含まれないはず）
	task4 := agent.NewSubTask("task-inject-4", agent.TaskKindSmart, "other target scan")
	task4.TargetID = 2
	task4.Status = agent.TaskStatusPending
	tm.InjectTask("task-inject-4", task4)

	// Target 1 の active タスクを取得
	active := tm.ActiveTasks(1)
	if len(active) != 2 {
		t.Fatalf("ActiveTasks(1): got %d, want 2", len(active))
	}

	// active に含まれるのは pending と running のみ
	ids := make(map[string]bool)
	for _, task := range active {
		ids[task.ID] = true
	}
	if !ids["task-inject-1"] {
		t.Error("ActiveTasks(1) should contain task-inject-1 (pending)")
	}
	if !ids["task-inject-2"] {
		t.Error("ActiveTasks(1) should contain task-inject-2 (running)")
	}
	if ids["task-inject-3"] {
		t.Error("ActiveTasks(1) should NOT contain task-inject-3 (completed)")
	}
	if ids["task-inject-4"] {
		t.Error("ActiveTasks(1) should NOT contain task-inject-4 (target 2)")
	}

	// Target 2 の active タスクを取得
	active2 := tm.ActiveTasks(2)
	if len(active2) != 1 {
		t.Fatalf("ActiveTasks(2): got %d, want 1", len(active2))
	}
	if active2[0].ID != "task-inject-4" {
		t.Errorf("ActiveTasks(2)[0].ID: got %q, want %q", active2[0].ID, "task-inject-4")
	}

	// 存在しない Target のタスクは空
	active3 := tm.ActiveTasks(999)
	if len(active3) != 0 {
		t.Errorf("ActiveTasks(999): got %d, want 0", len(active3))
	}
}

func TestTaskManager_DoneCh(t *testing.T) {
	// DoneCh は非 nil のチャネルを返すこと
	runner := newSmartTestRunner()
	events := make(chan agent.Event, 64)

	tm := agent.NewTaskManager(runner, nil, events, nil)

	ch := tm.DoneCh()
	if ch == nil {
		t.Fatal("DoneCh: got nil, want non-nil channel")
	}

	// InjectDone で送信した値が DoneCh から読み取れること
	go tm.InjectDone("test-done-id")

	select {
	case id := <-ch:
		if id != "test-done-id" {
			t.Errorf("DoneCh received: got %q, want %q", id, "test-done-id")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("DoneCh: timed out waiting for value")
	}
}
