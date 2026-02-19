// Package schema defines the shared JSON types exchanged between the TUI and the Brain (LLM).
package schema

// ActionType defines the kind of action the Brain wants to perform.
type ActionType string

const (
	// ActionRun はコマンド文字列を直接実行する。
	// Docker ツール or proposal_required: false のツールで使う。
	ActionRun ActionType = "run"

	// ActionPropose はホスト直接実行や高リスクコマンドをユーザーに提案する。
	// Brain はホストツールには常にこれを使う。
	ActionPropose ActionType = "propose"

	// ActionThink は発見内容を分析するだけで何も実行しない。
	ActionThink ActionType = "think"

	// ActionComplete はターゲットのアセスメント完了を宣言する。
	ActionComplete ActionType = "complete"

	// ActionMemory は脆弱性・認証情報・アーティファクトを memory に記録する。
	ActionMemory ActionType = "memory"

	// ActionAddTarget は横展開時に新ターゲットを追加する。
	// Brain がネットワーク内の別ホストを発見した際に使用する。
	ActionAddTarget ActionType = "add_target"

	// ActionCallMCP は MCP サーバーのツールを呼び出す。
	// Brain が MCP ツール（Playwright ブラウザ操作等）を使用する際に使用する。
	ActionCallMCP ActionType = "call_mcp"

	// ActionSpawnTask はバックグラウンドタスクを生成する。
	ActionSpawnTask ActionType = "spawn_task"

	// ActionWait は実行中の SubTask の完了を待つ。
	ActionWait ActionType = "wait"

	// ActionCheckTask は実行中の SubTask の部分出力を取得する。
	ActionCheckTask ActionType = "check_task"

	// ActionKillTask は実行中の SubTask をキャンセルする。
	ActionKillTask ActionType = "kill_task"

	// ActionSearchKnowledge はナレッジベース（HackTricks）を検索する。
	ActionSearchKnowledge ActionType = "search_knowledge"

	// ActionReadKnowledge はナレッジベースの特定記事を読み込む。
	ActionReadKnowledge ActionType = "read_knowledge"
)

// Action is the JSON payload emitted by the Brain (LLM).
//
// Brain は常に以下の形式で応答する:
//
//	{
//	  "thought": "port 80 open, running nikto",
//	  "action":  "run",
//	  "command": "nikto -h http://10.0.0.5/"
//	}
type Action struct {
	Thought string     `json:"thought"`
	Action  ActionType `json:"action"`
	Command string     `json:"command,omitempty"` // ActionRun / ActionPropose
	Memory  *Memory    `json:"memory,omitempty"`  // ActionMemory
	Target  string     `json:"target,omitempty"`  // ActionAddTarget: 追加するホスト

	// MCPServer は呼び出す MCP サーバーの名前（ActionCallMCP 時に使用）。
	MCPServer string         `json:"mcp_server,omitempty"`
	// MCPTool は呼び出す MCP ツールの名前（ActionCallMCP 時に使用）。
	MCPTool   string         `json:"mcp_tool,omitempty"`
	// MCPArgs は MCP ツールに渡す引数（ActionCallMCP 時に使用）。
	MCPArgs   map[string]any `json:"mcp_args,omitempty"`

	// Knowledge 関連フィールド
	KnowledgeQuery string `json:"knowledge_query,omitempty"` // search_knowledge 用
	KnowledgePath  string `json:"knowledge_path,omitempty"`  // read_knowledge 用

	// SubTask 関連フィールド
	TaskID       string `json:"task_id,omitempty"`        // wait/check_task/kill_task: 対象タスクID
	TaskKind     string `json:"task_kind,omitempty"`      // spawn_task: "runner" or "smart"
	TaskGoal     string `json:"task_goal,omitempty"`      // spawn_task: タスクの目的
	TaskMaxTurns int    `json:"task_max_turns,omitempty"` // spawn_task (smart): 最大ターン数
	TaskPort     int    `json:"task_port,omitempty"`      // spawn_task: メタデータ - ポート
	TaskService  string `json:"task_service,omitempty"`   // spawn_task: メタデータ - サービス名
	TaskPhase    string `json:"task_phase,omitempty"`     // spawn_task: メタデータ - フェーズ
}

// Memory は Brain がナレッジグラフに記録する発見物。
type Memory struct {
	Type        MemoryType `json:"type"`
	Title       string     `json:"title"`
	Description string     `json:"description"`
	Severity    string     `json:"severity,omitempty"` // critical/high/medium/low/info
}

// MemoryType は記録する情報の種別。
type MemoryType string

const (
	MemoryVulnerability MemoryType = "vulnerability" // 脆弱性
	MemoryCredential    MemoryType = "credential"    // 認証情報
	MemoryArtifact      MemoryType = "artifact"      // アーティファクト（取得ファイル等）
	MemoryNote          MemoryType = "note"           // その他メモ
)
