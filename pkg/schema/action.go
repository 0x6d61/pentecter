// Package schema defines the shared JSON types exchanged between the TUI and the Brain (LLM).
package schema

// ActionType represents the kind of action the Brain wants to perform.
type ActionType string

const (
	ActionRunTool  ActionType = "run_tool"
	ActionThink    ActionType = "think"
	ActionComplete ActionType = "complete"
)

// Action is the JSON payload emitted by the Brain (LLM).
type Action struct {
	Thought string     `json:"thought"`
	Action  ActionType `json:"action"`
	Tool    string     `json:"tool,omitempty"`
	Args    []string   `json:"args,omitempty"`
}
