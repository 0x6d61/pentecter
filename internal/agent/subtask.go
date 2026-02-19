// Package agent - subtask.go はバックグラウンドで実行されるサブタスクを定義する。
package agent

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/0x6d61/pentecter/internal/tools"
)

// TaskKind はサブタスクの種別を表す。
type TaskKind string

const (
	// TaskKindRunner は単一コマンドを実行するタスク。
	TaskKindRunner TaskKind = "runner"
	// TaskKindSmart は Brain を使った自律型サブエージェントタスク。
	TaskKindSmart TaskKind = "smart"
)

// TaskStatus はサブタスクの実行状態。
type TaskStatus string

const (
	TaskStatusPending   TaskStatus = "pending"
	TaskStatusRunning   TaskStatus = "running"
	TaskStatusCompleted TaskStatus = "completed"
	TaskStatusFailed    TaskStatus = "failed"
	TaskStatusCancelled TaskStatus = "cancelled"
)

// TaskMetadata はサブタスクに付与されるメタ情報。
type TaskMetadata struct {
	Port    int    `json:"port,omitempty"`
	Service string `json:"service,omitempty"`
	Phase   string `json:"phase,omitempty"`
}

// SubTask はバックグラウンドで実行されるタスクを表す。
type SubTask struct {
	ID          string
	Kind        TaskKind
	Goal        string
	Command     string
	Status      TaskStatus
	Metadata    TaskMetadata
	TargetID    int
	StartedAt   time.Time
	CompletedAt time.Time
	ExitCode    int
	Error       string
	MaxTurns    int
	TurnCount   int
	Findings    []string
	Entities    []tools.Entity

	// 非公開フィールド
	mu          sync.RWMutex
	outputLines []string
	lastReadIdx int
	done        chan struct{}
	cancel      context.CancelFunc
}

// NewSubTask はサブタスクを作成する。done チャネルを初期化する。
func NewSubTask(id string, kind TaskKind, goal string) *SubTask {
	return &SubTask{
		ID:     id,
		Kind:   kind,
		Goal:   goal,
		Status: TaskStatusPending,
		done:   make(chan struct{}),
	}
}

// AppendOutput は出力バッファに1行追加する。goroutine-safe。
func (st *SubTask) AppendOutput(line string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.outputLines = append(st.outputLines, line)
}

// ReadNewOutput は lastReadIdx 以降の新しい出力行を返す。
// カーソルは進めない（AdvanceReadCursor で明示的に進める）。
func (st *SubTask) ReadNewOutput() []string {
	st.mu.RLock()
	defer st.mu.RUnlock()

	if st.lastReadIdx >= len(st.outputLines) {
		return nil
	}
	// コピーを返す
	newLines := make([]string, len(st.outputLines)-st.lastReadIdx)
	copy(newLines, st.outputLines[st.lastReadIdx:])
	return newLines
}

// AdvanceReadCursor はリードカーソルを現在の出力末尾まで進める。
func (st *SubTask) AdvanceReadCursor() {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.lastReadIdx = len(st.outputLines)
}

// FullOutput は全出力行を改行で結合して返す。
func (st *SubTask) FullOutput() string {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return strings.Join(st.outputLines, "\n")
}

// Summary はタスクのサマリーテキストを返す。
// Runner: "[task-1] running (5 output lines): scan target"
// Smart:  "[task-1] running (turn 3/10, 5 output lines): enumerate services"
func (st *SubTask) Summary() string {
	st.mu.RLock()
	defer st.mu.RUnlock()

	lineCount := len(st.outputLines)

	if st.Kind == TaskKindSmart && st.MaxTurns > 0 {
		return fmt.Sprintf("[%s] %s (turn %d/%d, %d output lines): %s",
			st.ID, st.Status, st.TurnCount, st.MaxTurns, lineCount, st.Goal)
	}
	return fmt.Sprintf("[%s] %s (%d output lines): %s",
		st.ID, st.Status, lineCount, st.Goal)
}

// GetMetadata はメタデータのコピーを返す（goroutine-safe）。
func (st *SubTask) GetMetadata() TaskMetadata {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return st.Metadata
}

// Done は完了通知チャネルを返す。Complete() 時にクローズされる。
func (st *SubTask) Done() <-chan struct{} {
	return st.done
}

// Complete はタスクを完了としてマークし、done チャネルを閉じる。
// 1回だけ呼ぶこと。
func (st *SubTask) Complete() {
	close(st.done)
}

// Cancel はキャンセル関数を呼び出す（設定されている場合）。
func (st *SubTask) Cancel() {
	if st.cancel != nil {
		st.cancel()
	}
}

// SetCancel はキャンセル関数をセットする。
func (st *SubTask) SetCancel(fn context.CancelFunc) {
	st.cancel = fn
}
