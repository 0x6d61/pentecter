package agent

import "time"

// EventType は Agent から TUI へ送るイベントの種別。
type EventType string

const (
	// EventLog は通常のログ行（AI の思考・ツール出力・システムメッセージ）。
	EventLog EventType = "log"
	// EventProposal は Brain がエクスプロイト等の重要アクションを提案したとき。
	EventProposal EventType = "proposal"
	// EventComplete はターゲットのアセスメントが完了したとき。
	EventComplete EventType = "complete"
	// EventError はループ内でリカバリー不能なエラーが発生したとき。
	EventError EventType = "error"
	// EventAddTarget は横展開で新ターゲットを追加するとき。
	EventAddTarget EventType = "add_target"
	// EventStalled は連続失敗でユーザーの方針指示を待つとき。
	EventStalled EventType = "stalled"
	// EventTurnStart は Brain 思考サイクルの開始を示す。
	EventTurnStart EventType = "turn_start"
	// EventSubTaskLog はサブタスクの出力ログ。
	EventSubTaskLog EventType = "subtask_log"
	// EventSubTaskComplete はサブタスクの完了通知。
	EventSubTaskComplete EventType = "subtask_complete"

	// --- Block-based rendering events ---

	// EventThinkStart は Brain.Think() の開始を示す（スピナー開始）。
	EventThinkStart EventType = "think_start"
	// EventThinkDone は Brain.Think() の完了を示す（Completed in Xs）。
	EventThinkDone EventType = "think_done"
	// EventCmdStart はコマンド実行の開始を示す（コマンド表示）。
	EventCmdStart EventType = "cmd_start"
	// EventCmdOutput はコマンド出力の1行を示す（BlockCommand の Output に追記）。
	EventCmdOutput EventType = "cmd_output"
	// EventCmdDone はコマンド実行の完了を示す（折りたたみ確定）。
	EventCmdDone EventType = "cmd_done"
	// EventSubTaskStart はサブタスク開始を示す（スピナー表示）。
	EventSubTaskStart EventType = "subtask_start"
)

// Event は Agent ループから TUI へ送るメッセージ。
type Event struct {
	TargetID   int       // どのターゲットのイベントか（TUI のルーティング用）
	Type       EventType
	Source     LogSource // EventLog 時に使用
	Message    string
	Proposal   *Proposal // EventProposal 時に使用
	NewHost    string    // EventAddTarget 時に使用
	TurnNumber int       // EventTurnStart 時のターン番号
	ExitCode   int       // EventCmdDone 時の exit code
	TaskID     string    // SubTask 関連イベント時の taskID

	// Block-based rendering fields
	Duration   time.Duration // EventThinkDone, EventCmdDone のかかった時間
	OutputLine string        // EventCmdOutput の出力行
}
