// Package agent - task_runner.go は単一コマンドをバックグラウンドで実行する TaskRunner を定義する。
package agent

import (
	"context"
	"time"

	"github.com/0x6d61/pentecter/internal/mcp"
	"github.com/0x6d61/pentecter/internal/tools"
)

// TaskRunner は SubTask（runner kind）のコマンドを実行する。
type TaskRunner struct {
	runner *tools.CommandRunner
	mcpMgr *mcp.MCPManager
	events chan<- Event
}

// NewTaskRunner は TaskRunner を構築する。
func NewTaskRunner(runner *tools.CommandRunner, mcpMgr *mcp.MCPManager, events chan<- Event) *TaskRunner {
	return &TaskRunner{
		runner: runner,
		mcpMgr: mcpMgr,
		events: events,
	}
}

// Run はサブタスクのコマンドを実行する。完了まで blocking する。
func (tr *TaskRunner) Run(ctx context.Context, task *SubTask) {
	task.Status = TaskStatusRunning
	task.StartedAt = time.Now()

	// コマンドが空の場合はエラー
	if task.Command == "" {
		task.Status = TaskStatusFailed
		task.Error = "command is empty"
		task.CompletedAt = time.Now()
		task.Complete()
		tr.emitComplete(task)
		return
	}

	// ForceRun で実行（承認チェックなし）
	linesCh, resultCh := tr.runner.ForceRun(ctx, task.Command)

	// ストリーム出力を収集
	for line := range linesCh {
		if line.Content == "" {
			continue
		}
		task.AppendOutput(line.Content)
		tr.emit(Event{
			Type:    EventSubTaskLog,
			TaskID:  task.ID,
			Source:  SourceTool,
			Message: line.Content,
		})
	}

	// 結果を取得
	result := <-resultCh
	task.ExitCode = result.ExitCode
	task.CompletedAt = time.Now()

	if result.Err != nil {
		task.Status = TaskStatusFailed
		task.Error = result.Err.Error()
	} else if result.ExitCode != 0 {
		// exit code が非ゼロでもコンテキストキャンセルの可能性をチェック
		if ctx.Err() != nil {
			task.Status = TaskStatusCancelled
			task.Error = "cancelled"
		} else {
			task.Status = TaskStatusFailed
			task.Error = "non-zero exit code"
		}
	} else {
		task.Status = TaskStatusCompleted
	}

	// Entity 抽出結果をタスクに保存
	if result.Entities != nil {
		task.Entities = result.Entities
	}

	task.Complete()
	tr.emitComplete(task)
}

// emit はイベントを送信する（ブロックしない）。
func (tr *TaskRunner) emit(e Event) {
	select {
	case tr.events <- e:
	default:
	}
}

// emitComplete は完了イベントを送信する。
func (tr *TaskRunner) emitComplete(task *SubTask) {
	tr.emit(Event{
		Type:    EventSubTaskComplete,
		TaskID:  task.ID,
		Message: task.Summary(),
	})
}
