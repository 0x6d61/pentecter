// Package agent - loop_tasks.go は Loop の SubTask 関連ハンドラを定義する。
package agent

import (
	"context"
	"fmt"
	"strings"

	"github.com/0x6d61/pentecter/pkg/schema"
)

// drainCompletedTasks は完了済みサブタスクの結果を取り出し、テキストとして返す。
// Brain.Think() の直前に呼ばれ、結果が lastToolOutput に注入される。
func (l *Loop) drainCompletedTasks() string {
	if l.taskMgr == nil {
		return ""
	}
	completed := l.taskMgr.DrainCompleted()
	if len(completed) == 0 {
		return ""
	}
	var sb strings.Builder
	for _, task := range completed {
		fmt.Fprintf(&sb, "=== SubTask Completed: %s ===\n", task.ID)
		sb.WriteString(l.buildTaskResult(task))
		sb.WriteString("\n")
	}
	return sb.String()
}

// handleSpawnTask は spawn_task アクションを処理する。
func (l *Loop) handleSpawnTask(ctx context.Context, action *schema.Action) {
	if l.taskMgr == nil {
		l.emit(Event{Type: EventLog, Source: SourceSystem,
			Message: "TaskManager not configured — cannot spawn tasks"})
		l.lastToolOutput = "Error: TaskManager not configured"
		return
	}

	req := SpawnTaskRequest{
		Kind:       TaskKindSmart,
		Goal:       action.TaskGoal,
		Command:    action.Command,
		TargetHost: l.target.Host,
		TargetID:   l.target.ID,
		MaxTurns:   action.TaskMaxTurns,
		Metadata: TaskMetadata{
			Port:    action.TaskPort,
			Service: action.TaskService,
			Phase:   action.TaskPhase,
		},
	}

	taskID, err := l.taskMgr.SpawnTask(ctx, req)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to spawn task: %v", err)
		l.emit(Event{Type: EventLog, Source: SourceSystem, Message: errMsg})
		l.lastToolOutput = "Error: " + err.Error()
		return
	}

	// Block-based rendering event
	l.emit(Event{
		Type:    EventSubTaskStart,
		TaskID:  taskID,
		Message: req.Goal,
	})

	msg := fmt.Sprintf("Task spawned: %s (goal=%s)", taskID, req.Goal)
	l.emit(Event{Type: EventLog, Source: SourceSystem, Message: msg})
	l.lastToolOutput = msg
}

// handleWait は wait アクションを処理する。指定タスクの完了を待つ。
func (l *Loop) handleWait(ctx context.Context, action *schema.Action) {
	if l.taskMgr == nil {
		l.lastToolOutput = "Error: TaskManager not configured"
		return
	}

	var doneID string
	if action.TaskID != "" {
		ok := l.taskMgr.WaitTask(ctx, action.TaskID)
		if !ok {
			l.lastToolOutput = fmt.Sprintf("Error: wait for task %s cancelled or not found", action.TaskID)
			return
		}
		doneID = action.TaskID
	} else {
		doneID = l.taskMgr.WaitAny(ctx)
		if doneID == "" {
			l.lastToolOutput = "Error: wait cancelled (context done)"
			return
		}
	}

	task, ok := l.taskMgr.GetTask(doneID)
	if !ok {
		l.lastToolOutput = fmt.Sprintf("Error: task %s not found after wait", doneID)
		return
	}

	l.lastToolOutput = l.buildTaskResult(task)

	// Post-wait drain: 待機中に届いたユーザーメッセージを回収
	if msg := l.drainUserMsg(); msg != "" {
		l.pendingUserMsg = msg
	}
}

// handleKillTask は kill_task アクションを処理する。
func (l *Loop) handleKillTask(action *schema.Action) {
	if l.taskMgr == nil {
		l.lastToolOutput = "Error: TaskManager not configured"
		return
	}

	err := l.taskMgr.KillTask(action.TaskID)
	if err != nil {
		l.lastToolOutput = fmt.Sprintf("Error: %v", err)
		return
	}

	l.lastToolOutput = fmt.Sprintf("Task %s cancelled", action.TaskID)
	l.emit(Event{Type: EventLog, Source: SourceSystem,
		Message: fmt.Sprintf("Task %s cancelled", action.TaskID)})
}

// buildTaskResult はサブタスクの完了結果テキストを組み立てる。
func (l *Loop) buildTaskResult(task *SubTask) string {
	var sb strings.Builder
	sb.WriteString(task.Summary())
	sb.WriteString("\n")

	// Findings を追加
	if len(task.Findings) > 0 {
		sb.WriteString("--- findings ---\n")
		for _, f := range task.Findings {
			sb.WriteString("- ")
			sb.WriteString(f)
			sb.WriteString("\n")
		}
	}

	// 出力（2000文字に制限）
	output := task.FullOutput()
	if output != "" {
		sb.WriteString("--- output ---\n")
		if len(output) > 2000 {
			sb.WriteString(output[:2000])
			sb.WriteString("\n... (truncated)\n")
		} else {
			sb.WriteString(output)
			sb.WriteString("\n")
		}
	}

	// Entity をターゲットに追加
	if len(task.Entities) > 0 {
		l.target.AddEntities(task.Entities)
	}

	return sb.String()
}
