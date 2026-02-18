// Package tools provides the generic async tool runner and YAML-driven registry.
package tools

import "time"

// OutputLine はツール生出力の1行を表す。
type OutputLine struct {
	Time    time.Time
	Content string
	IsError bool // stderr の場合 true
}

// Entity はツール出力から抽出された単一の発見物。
type Entity struct {
	Type    EntityType
	Value   string
	Context string // 抽出元の行（参照用）
}

// EntityType は発見物の種別。
type EntityType string

const (
	EntityPort EntityType = "port"
	EntityCVE  EntityType = "cve"
	EntityURL  EntityType = "url"
	EntityIP   EntityType = "ip"
)

// ToolResult はツール実行の完了結果をまとめたもの。
//
// データは3層に分かれる:
//   - RawLines     : 生テキスト全行。Log Store に保存し Agent がいつでも参照できる。
//   - Truncated    : 切り捨て済みテキスト。Brain の即時コンテキストへ渡す。
//   - Entities     : 抽出済み Entity。ナレッジグラフへ書き込む。
type ToolResult struct {
	ID       string // "nmap@10.0.0.5@1706000000" のような一意キー
	ToolName string
	Target   string
	Args     []string
	ExitCode int

	RawLines  []OutputLine // Log Store 用（全行保存）
	Truncated string       // Brain 用（切り捨て済みテキスト）
	Entities  []Entity     // ナレッジグラフ用

	StartedAt  time.Time
	FinishedAt time.Time
	Err        error
}
