package agent

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
	// EventCommandResult はコマンド実行結果のサマリー。
	EventCommandResult EventType = "command_result"
	// EventSubTaskLog はサブタスクの出力ログ。
	EventSubTaskLog EventType = "subtask_log"
	// EventSubTaskComplete はサブタスクの完了通知。
	EventSubTaskComplete EventType = "subtask_complete"
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
	ExitCode   int       // EventCommandResult 時の exit code
	TaskID     string    // SubTask 関連イベント時の taskID
}
