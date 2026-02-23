// Package agent - smart_subagent.go は小型 LLM を使って多段タスクを自律実行するサブエージェント。
package agent

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/0x6d61/pentecter/internal/brain"
	"github.com/0x6d61/pentecter/internal/mcp"
	"github.com/0x6d61/pentecter/internal/tools"
	"github.com/0x6d61/pentecter/internal/tools/webfuzz"
	"github.com/0x6d61/pentecter/pkg/schema"
)

// SmartSubAgent は小型 LLM を使って多段タスクを自律実行するサブエージェント。
type SmartSubAgent struct {
	br         brain.Brain
	runner     *tools.CommandRunner
	mcpMgr     *mcp.MCPManager
	events     chan<- Event
	attackData *AttackDataTree
	targetHost string
	memDir     string // webfuzz raw output 用
}

// NewSmartSubAgent は SmartSubAgent を構築する。
func NewSmartSubAgent(br brain.Brain, runner *tools.CommandRunner, mcpMgr *mcp.MCPManager, events chan<- Event, attackData *AttackDataTree, targetHost string, memDir string) *SmartSubAgent {
	// webfuzz 内部ツールを CommandRunner に登録
	var tree webfuzz.TreeUpdater
	if attackData != nil {
		tree = &webfuzzTreeAdapter{tree: attackData}
	}
	runner.RegisterInternalTool("webfuzz", webfuzz.NewWebfuzzTool(tree, targetHost))

	return &SmartSubAgent{
		br:         br,
		runner:     runner,
		mcpMgr:     mcpMgr,
		events:     events,
		attackData: attackData,
		targetHost: targetHost,
		memDir:     memDir,
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

	type cmdRecord struct {
		cmd      string
		exitCode int
	}
	var history []cmdRecord

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

		// AttackDataTree の intel を取得（SubAgent 用: [BACKGROUND] セクション除外）
		var reconQueue string
		if sa.attackData != nil {
			reconQueue = sa.attackData.RenderIntelForSubAgent()
		}

		// CommandHistory を構築（直近の履歴要約）
		var historyText string
		if len(history) > 0 {
			var hb strings.Builder
			for _, h := range history {
				fmt.Fprintf(&hb, "- `%s` → exit %d\n", h.cmd, h.exitCode)
			}
			historyText = hb.String()
		}

		input := brain.Input{
			TargetSnapshot:  fmt.Sprintf(`{"host":%q,"task_goal":%q}`, targetHost, task.Goal),
			TaskInstruction: task.Command,
			ToolOutput:      lastOutput,
			LastCommand:     lastCommand,
			LastExitCode:    lastExitCode,
			TurnCount:       turn,
			ReconQueue:      reconQueue,
			CommandHistory:  historyText,
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
			lastCommand = action.Command
			linesCh, resultCh := sa.runner.ForceRun(ctx, action.Command)

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

			// コマンド履歴を記録（直近10件）
			history = append(history, cmdRecord{cmd: action.Command, exitCode: result.ExitCode})
			if len(history) > 10 {
				history = history[len(history)-10:]
			}

			// AttackDataTree にパース結果を反映
			if sa.attackData != nil {
				_ = DetectAndParse(action.Command, result.Truncated, sa.attackData, sa.targetHost)
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
			// Pending タスクが残っている場合は complete を拒否してループ継続
			if sa.attackData != nil && sa.attackData.HasPending() {
				sa.emitLog(task, SourceSystem,
					fmt.Sprintf("SmartSubAgent %s: complete rejected — %d pending tasks remain",
						task.ID, sa.attackData.CountPending()))
				lastOutput = fmt.Sprintf("Cannot complete: %d pending tasks remain. Check RECON INTEL and continue working.", sa.attackData.CountPending())
				continue
			}
			task.Status = TaskStatusCompleted
			task.CompletedAt = time.Now()
			task.Complete()
			sa.emitLog(task, SourceSystem, fmt.Sprintf("SmartSubAgent %s completed", task.ID))
			sa.emitTaskComplete(task)
			return

		case schema.ActionThink:
			// Thought は既にログ済み。ループ継続。

		default:
			// SubAgent は run/think/memory/complete のみサポート。
			// wait 等の unsupported action は Brain にフィードバックしてリトライさせる。
			msg := fmt.Sprintf("Action %q is not available in SubAgent. Use run/think/memory/complete only.", action.Action)
			task.AppendOutput(msg)
			sa.emitLog(task, SourceSystem,
				fmt.Sprintf("SmartSubAgent %s: unsupported action %q", task.ID, action.Action))
			lastOutput = msg
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
