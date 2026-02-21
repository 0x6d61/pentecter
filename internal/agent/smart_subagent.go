// Package agent - smart_subagent.go は小型 LLM を使って多段タスクを自律実行するサブエージェント。
package agent

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/0x6d61/pentecter/internal/brain"
	"github.com/0x6d61/pentecter/internal/mcp"
	"github.com/0x6d61/pentecter/internal/tools"
	"github.com/0x6d61/pentecter/pkg/schema"
)

// SmartSubAgent は小型 LLM を使って多段タスクを自律実行するサブエージェント。
type SmartSubAgent struct {
	br         brain.Brain
	runner     *tools.CommandRunner
	mcpMgr     *mcp.MCPManager
	events     chan<- Event
	reconTree  *ReconTree
	targetHost string
}

// NewSmartSubAgent は SmartSubAgent を構築する。
func NewSmartSubAgent(br brain.Brain, runner *tools.CommandRunner, mcpMgr *mcp.MCPManager, events chan<- Event, reconTree *ReconTree, targetHost string) *SmartSubAgent {
	return &SmartSubAgent{
		br:         br,
		runner:     runner,
		mcpMgr:     mcpMgr,
		events:     events,
		reconTree:  reconTree,
		targetHost: targetHost,
	}
}

// Run はサブタスクを自律ループで実行する。完了まで blocking する。
func (sa *SmartSubAgent) Run(ctx context.Context, task *SubTask, targetHost string) {
	task.Status = TaskStatusRunning
	task.StartedAt = time.Now()

	// デフォルトの MaxTurns
	if task.MaxTurns == 0 {
		task.MaxTurns = 10
	}

	sa.emitLog(task, SourceSystem, fmt.Sprintf("SmartSubAgent %s started: %s", task.ID, task.Goal))

	var lastCommand string
	var lastOutput string
	var lastExitCode int

	for turn := 1; turn <= task.MaxTurns; turn++ {
		// コンテキストキャンセルチェック
		select {
		case <-ctx.Done():
			task.Status = TaskStatusCancelled
			task.Error = "cancelled"
			task.CompletedAt = time.Now()
			task.Complete()
			sa.emitLog(task, SourceSystem, fmt.Sprintf("SmartSubAgent %s cancelled", task.ID))
			sa.emitTaskComplete(task)
			return
		default:
		}

		task.TurnCount = turn

		// Brain に渡す Input を構築
		// 初回ターンのみ task.Command をユーザーメッセージとして注入（詳細な指示プロンプト）
		userMsg := ""
		if turn == 1 && task.Command != "" {
			userMsg = task.Command
		}
		input := brain.Input{
			TargetSnapshot: fmt.Sprintf(`{"host":%q,"task_goal":%q}`, targetHost, task.Goal),
			ToolOutput:     lastOutput,
			LastCommand:    lastCommand,
			LastExitCode:   lastExitCode,
			TurnCount:      turn,
			UserMessage:    userMsg,
		}

		// Brain に思考を依頼
		action, err := sa.br.Think(ctx, input)
		if err != nil {
			task.Status = TaskStatusFailed
			task.Error = fmt.Sprintf("brain error: %v", err)
			task.AppendOutput(fmt.Sprintf("[error] %s", err))
			task.CompletedAt = time.Now()
			task.Complete()
			sa.emitLog(task, SourceSystem, fmt.Sprintf("SmartSubAgent %s failed: %v", task.ID, err))
			sa.emitTaskComplete(task)
			return
		}

		// Thought をログに追加
		if action.Thought != "" {
			task.AppendOutput("[think] " + action.Thought)
			sa.emitLog(task, SourceAI, action.Thought)
		}

		switch action.Action {
		case schema.ActionRun:
			cmd := EnsureFfufSilent(action.Command)
			lastCommand = cmd
			linesCh, resultCh := sa.runner.ForceRun(ctx, cmd)

			// ストリーム出力を収集
			for line := range linesCh {
				if line.Content != "" {
					task.AppendOutput(line.Content)
				}
			}

			// 結果を取得
			result := <-resultCh
			lastExitCode = result.ExitCode
			lastOutput = result.Truncated

			// ReconTree にパース結果を反映
			if sa.reconTree != nil {
				parseOutput := result.Truncated
				if ffufPath := ExtractFfufOutputPath(cmd); ffufPath != "" {
					if data, err := os.ReadFile(ffufPath); err == nil {
						parseOutput = string(data)
					}
				}
				_ = DetectAndParse(cmd, parseOutput, sa.reconTree, sa.targetHost)
			}

			// Entity 抽出結果をタスクに追加
			if result.Entities != nil {
				task.Entities = append(task.Entities, result.Entities...)
			}

		case schema.ActionMemory:
			if action.Memory != nil {
				finding := fmt.Sprintf("[%s] %s: %s",
					action.Memory.Type, action.Memory.Title, action.Memory.Description)
				task.Findings = append(task.Findings, finding)
				task.AppendOutput("[memory] " + action.Memory.Title)
				sa.emitLog(task, SourceAI, fmt.Sprintf("Memory: %s", action.Memory.Title))
			}

		case schema.ActionComplete:
			task.Status = TaskStatusCompleted
			task.CompletedAt = time.Now()
			task.Complete()
			sa.emitLog(task, SourceSystem, fmt.Sprintf("SmartSubAgent %s completed", task.ID))
			sa.emitTaskComplete(task)
			return

		case schema.ActionThink:
			// Thought は既にログ済み。ループ継続。

		default:
			task.AppendOutput("Unsupported action in SubAgent: " + string(action.Action))
			sa.emitLog(task, SourceSystem,
				fmt.Sprintf("SmartSubAgent %s: unsupported action %q", task.ID, action.Action))
		}
	}

	// MaxTurns に到達
	task.Status = TaskStatusCompleted
	task.CompletedAt = time.Now()
	task.Complete()
	sa.emitLog(task, SourceSystem,
		fmt.Sprintf("SmartSubAgent %s completed (max turns %d reached)", task.ID, task.MaxTurns))
	sa.emitTaskComplete(task)
}

// emitLog はサブタスクのログイベントを送信する（ブロックしない）。
func (sa *SmartSubAgent) emitLog(task *SubTask, source LogSource, msg string) {
	select {
	case sa.events <- Event{
		Type:    EventSubTaskLog,
		TaskID:  task.ID,
		Source:  source,
		Message: msg,
	}:
	default:
	}
}

// emitTaskComplete はサブタスクの完了イベントを送信する。
func (sa *SmartSubAgent) emitTaskComplete(task *SubTask) {
	select {
	case sa.events <- Event{
		Type:    EventSubTaskComplete,
		TaskID:  task.ID,
		Message: task.Summary(),
	}:
	default:
	}
}
