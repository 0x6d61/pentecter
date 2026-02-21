// Package agent - task_manager.go はサブタスクのライフサイクルを管理する TaskManager を定義する。
package agent

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/0x6d61/pentecter/internal/brain"
	"github.com/0x6d61/pentecter/internal/mcp"
	"github.com/0x6d61/pentecter/internal/tools"
)

// TaskManager はサブタスクの生成・追跡・終了を管理する。
type TaskManager struct {
	mu       sync.RWMutex
	tasks    map[string]*SubTask
	nextID   atomic.Int64
	runner   *tools.CommandRunner
	mcpMgr   *mcp.MCPManager
	events   chan<- Event
	subBrain brain.Brain
	doneCh   chan string // バッファ: 64
}

// SpawnTaskRequest はサブタスクの生成リクエスト。
type SpawnTaskRequest struct {
	Kind       TaskKind
	Goal       string
	Command    string
	Metadata   TaskMetadata
	TargetID   int
	TargetHost string
	MaxTurns   int
	ReconTree  *ReconTree
}

// NewTaskManager は TaskManager を構築する。
func NewTaskManager(runner *tools.CommandRunner, mcpMgr *mcp.MCPManager, events chan<- Event, subBrain brain.Brain) *TaskManager {
	return &TaskManager{
		tasks:    make(map[string]*SubTask),
		runner:   runner,
		mcpMgr:   mcpMgr,
		events:   events,
		subBrain: subBrain,
		doneCh:   make(chan string, 64),
	}
}

// SpawnTask は新しいサブタスクを生成し、バックグラウンドで実行する。
func (tm *TaskManager) SpawnTask(ctx context.Context, req SpawnTaskRequest) (string, error) {
	id := fmt.Sprintf("task-%d", tm.nextID.Add(1))

	task := NewSubTask(id, req.Kind, req.Goal)
	task.Command = req.Command
	task.Metadata = req.Metadata
	task.TargetID = req.TargetID
	task.MaxTurns = req.MaxTurns

	// キャンセル用コンテキスト
	taskCtx, cancel := context.WithCancel(ctx)
	task.SetCancel(cancel)

	tm.mu.Lock()
	tm.tasks[id] = task
	tm.mu.Unlock()

	if tm.subBrain == nil {
		task.Status = TaskStatusFailed
		task.Error = "sub-brain is not configured"
		task.Complete()
		cancel()
		return id, fmt.Errorf("sub-brain is not configured for smart tasks")
	}
	sa := NewSmartSubAgent(tm.subBrain, tm.runner, tm.mcpMgr, tm.events, req.ReconTree, req.TargetHost)
	go func() {
		sa.Run(taskCtx, task, req.TargetHost)
		select {
		case tm.doneCh <- id:
		case <-taskCtx.Done():
			// context cancelled — 完了通知は不要
		}
	}()

	return id, nil
}

// GetTask は指定 ID のサブタスクを返す。
func (tm *TaskManager) GetTask(id string) (*SubTask, bool) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	task, ok := tm.tasks[id]
	return task, ok
}

// InjectTask はテスト用にタスクを直接注入する。
func (tm *TaskManager) InjectTask(id string, task *SubTask) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.tasks[id] = task
}

// InjectDone はテスト用に完了通知を doneCh に送信する。
func (tm *TaskManager) InjectDone(id string) {
	tm.doneCh <- id
}

// WaitAny は完了したサブタスクの ID を1つ返す。
// コンテキストがキャンセルされた場合は空文字を返す。
func (tm *TaskManager) WaitAny(ctx context.Context) string {
	select {
	case id := <-tm.doneCh:
		return id
	case <-ctx.Done():
		return ""
	}
}

// WaitTask は指定 ID のサブタスクの完了を待つ。
// 完了した場合は true、コンテキストキャンセルの場合は false を返す。
func (tm *TaskManager) WaitTask(ctx context.Context, id string) bool {
	tm.mu.RLock()
	task, ok := tm.tasks[id]
	tm.mu.RUnlock()
	if !ok {
		return false
	}

	select {
	case <-task.Done():
		return true
	case <-ctx.Done():
		return false
	}
}

// KillTask は指定 ID のサブタスクをキャンセルする。
func (tm *TaskManager) KillTask(id string) error {
	tm.mu.RLock()
	task, ok := tm.tasks[id]
	tm.mu.RUnlock()
	if !ok {
		return fmt.Errorf("task not found: %s", id)
	}

	task.Cancel()
	return nil
}

// ActiveTasks は指定ターゲットの実行中（pending/running）サブタスクを返す。
func (tm *TaskManager) ActiveTasks(targetID int) []*SubTask {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	var active []*SubTask
	for _, task := range tm.tasks {
		if task.TargetID == targetID &&
			(task.Status == TaskStatusPending || task.Status == TaskStatusRunning) {
			active = append(active, task)
		}
	}
	return active
}

// AllTasks は指定ターゲットの全サブタスクを返す。
func (tm *TaskManager) AllTasks(targetID int) []*SubTask {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	var all []*SubTask
	for _, task := range tm.tasks {
		if task.TargetID == targetID {
			all = append(all, task)
		}
	}
	return all
}

// DrainCompleted は完了済みタスクを非ブロッキングですべて取り出して返す。
// 取り出されたタスクは次回の DrainCompleted では返されない。
func (tm *TaskManager) DrainCompleted() []*SubTask {
	var completed []*SubTask
	for {
		select {
		case id := <-tm.doneCh:
			tm.mu.RLock()
			if task, ok := tm.tasks[id]; ok {
				completed = append(completed, task)
			}
			tm.mu.RUnlock()
		default:
			return completed
		}
	}
}

// DoneCh は完了通知チャネルを返す（外部の select 用）。
func (tm *TaskManager) DoneCh() <-chan string {
	return tm.doneCh
}
