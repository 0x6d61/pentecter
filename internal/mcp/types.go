// Package mcp は MCP (Model Context Protocol) クライアントを提供する。
// JSON-RPC 2.0 over stdio で MCP サーバーと通信し、
// ツールの列挙・呼び出しを行う。
package mcp

// ToolSchema は MCP サーバーの tools/list レスポンスにおけるツール定義
type ToolSchema struct {
	// Server はこのツールが所属する MCP サーバー名
	Server string `json:"-"`
	// Name はツールの一意な名前
	Name string `json:"name"`
	// Description はツールの説明
	Description string `json:"description"`
	// InputSchema はツール引数の JSON Schema
	InputSchema map[string]any `json:"inputSchema"`
}

// CallResult は MCP tools/call の実行結果
type CallResult struct {
	// Content はレスポンスのコンテンツブロック群
	Content []ContentBlock `json:"content"`
	// IsError はツール実行がエラーだったかどうか
	IsError bool `json:"isError,omitempty"`
}

// ContentBlock は MCP レスポンス内の単一コンテンツブロック
type ContentBlock struct {
	// Type はコンテンツの種類（"text", "image", "resource"）
	Type string `json:"type"`
	// Text はテキストコンテンツ（Type が "text" の場合）
	Text string `json:"text,omitempty"`
}

// ServerConfig は YAML 設定ファイルにおける MCP サーバー定義
type ServerConfig struct {
	// Name はサーバーの識別名
	Name string `yaml:"name"`
	// Command は起動するコマンド
	Command string `yaml:"command"`
	// Args はコマンドライン引数
	Args []string `yaml:"args"`
	// Env はサーバーに渡す環境変数（${VAR} はホスト環境から展開される）
	Env map[string]string `yaml:"env,omitempty"`
	// ProposalRequired が true の場合、Brain はツール呼び出し前にユーザー承認を求める
	ProposalRequired *bool `yaml:"proposal_required,omitempty"`
}

// MCPConfig は MCP 設定ファイルのトップレベル構造体
type MCPConfig struct {
	// Servers は設定された MCP サーバーの一覧
	Servers []ServerConfig `yaml:"servers"`
}
