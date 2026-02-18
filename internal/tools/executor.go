package tools

import "context"

// Executor は単一ツールの実行インターフェース。
// YAMLExecutor（subprocess）と MCPExecutor（MCP サーバー）の両方が実装する。
type Executor interface {
	// Execute はツールを非同期実行する。
	// args は map[string]any 形式（Brain の Action.Args と同じ）。
	// 実行中の生出力は lines チャネルにストリームされ、
	// 完了時に result チャネルに ToolResult が送信される。
	Execute(ctx context.Context, store *LogStore, args map[string]any) (<-chan OutputLine, <-chan *ToolResult)

	// ExecutorType は実装の種別を返す（"yaml" or "mcp"）。
	ExecutorType() string
}
