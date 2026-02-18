// Package schema defines the shared JSON types exchanged between the TUI and the Brain (LLM).
package schema

// ActionType represents the kind of action the Brain wants to perform.
type ActionType string

const (
	ActionRunTool  ActionType = "run_tool"
	ActionThink    ActionType = "think"
	ActionComplete ActionType = "complete"
	// ActionPropose は重要アクション（エクスプロイト等）を提案しユーザー承認を求める。
	ActionPropose ActionType = "propose"
)

// Action is the JSON payload emitted by the Brain (LLM).
//
// Args は map[string]any 形式で統一する。
//   - YAML ツール: ToolDef.ArgsTemplate で CLI 引数に変換される
//   - MCP ツール:  そのまま MCP tools/call の arguments として渡される
//
// 例（nmap）:
//
//	{
//	  "thought": "start port scan",
//	  "action":  "run_tool",
//	  "tool":    "nmap",
//	  "args":    {"target": "10.0.0.5", "ports": "21,22,80", "flags": ["-sV"]}
//	}
type Action struct {
	Thought string         `json:"thought"`
	Action  ActionType     `json:"action"`
	Tool    string         `json:"tool,omitempty"`
	Args    map[string]any `json:"args,omitempty"`
}
