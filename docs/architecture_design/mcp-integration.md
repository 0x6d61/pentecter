# MCP（Model Context Protocol）統合設計

## 概要

pentecter に MCP クライアントを統合し、外部 MCP サーバー（@playwright/mcp 等）の機能を Brain から呼び出せるようにする。

## 背景

- Web アプリ操作（リンククリック、フォーム入力、ページ読み取り）ができない問題の解決
- `design-philosophy.md` で既に `call_mcp` アクションの方向性を定義済み
- MCP はツールスキーマを持つため Brain が引数を自律生成できる

---

## アーキテクチャ

```
cmd/pentecter/main.go
  │
  ├─ mcp.NewManager(configPath)     ← MCP サーバー管理
  │    ├─ StartAll()               ← サーバープロセス起動
  │    ├─ ListAllTools() → schemas ← Brain に注入するスキーマ一覧
  │    └─ CallTool(server, tool, args) → result
  │
  ├─ brain.New(cfg)                ← ToolNames + MCP schemas を注入
  │
  └─ agent.NewTeam(cfg)            ← MCPManager を渡す
       └─ Loop.Run()
            └─ case ActionCallMCP  ← MCP ツール呼び出しディスパッチ
```

---

## 新パッケージ: internal/mcp/

| ファイル | 責務 |
|---------|------|
| types.go | MCP 関連の型定義（ToolSchema, CallResult, ServerConfig 等） |
| config.go | YAML 設定の読み込み・バリデーション |
| client.go | MCPClient — 1サーバーとの JSON-RPC 2.0 stdio 通信 |
| manager.go | MCPManager — サーバーのライフサイクル管理 |

---

## MCP 通信方式

### なぜ自前実装か

mark3labs/mcp-go は便利だが依存が大きい。pentecter に必要な MCP 操作は3つだけ:

1. `initialize` — ハンドシェイク
2. `tools/list` — ツール一覧取得
3. `tools/call` — ツール実行

JSON-RPC 2.0 over stdio は約 150 行で実装でき、外部依存を増やさずに済む。

### MCPClient インターフェース

```go
type MCPClient struct {
    cmd    *exec.Cmd
    stdin  io.WriteCloser
    stdout *bufio.Reader
    nextID int64
}

func NewStdioClient(command string, args []string, env []string) (*MCPClient, error)
func (c *MCPClient) Initialize(ctx context.Context) error
func (c *MCPClient) ListTools(ctx context.Context) ([]ToolSchema, error)
func (c *MCPClient) CallTool(ctx context.Context, name string, args map[string]any) (*CallResult, error)
func (c *MCPClient) Close() error
```

### JSON-RPC 2.0 プロトコル

リクエスト:

```json
{"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
```

レスポンス:

```json
{"jsonrpc": "2.0", "id": 1, "result": {"tools": [...]}}
```

---

## MCP サーバー設定

### 設定ファイル: config/mcp.yaml

```yaml
servers:
  - name: playwright
    command: npx
    args: ["@playwright/mcp@latest"]
    env:
      DISPLAY: ":0"
    proposal_required: false

  - name: shodan
    command: python3
    args: ["-m", "shodan_mcp"]
    env:
      SHODAN_API_KEY: "${SHODAN_API_KEY}"
    proposal_required: true
```

### ServerConfig フィールド一覧

| フィールド | 型 | 説明 |
|-----------|---|------|
| name | string | サーバー識別子（Brain が参照する名前） |
| command | string | 実行コマンド（npx, python3 等） |
| args | []string | コマンド引数 |
| env | map[string]string | 環境変数（`${VAR}` は展開される） |
| proposal_required | *bool | 承認要否（nil = false） |

---

## MCPManager

```go
type MCPManager struct {
    clients map[string]*MCPClient
    configs []ServerConfig
}

func NewManager(configPath string) (*MCPManager, error)
func (m *MCPManager) StartAll(ctx context.Context) error
func (m *MCPManager) ListAllTools() []ToolSchema
func (m *MCPManager) CallTool(ctx context.Context, server, tool string, args map[string]any) (*CallResult, error)
func (m *MCPManager) Close() error
```

---

## schema.Action の拡張

```go
const ActionCallMCP ActionType = "call_mcp"

type Action struct {
    Thought   string         `json:"thought"`
    Action    ActionType     `json:"action"`
    Command   string         `json:"command,omitempty"`
    Memory    *Memory        `json:"memory,omitempty"`
    Target    string         `json:"target,omitempty"`
    MCPServer string         `json:"mcp_server,omitempty"`
    MCPTool   string         `json:"mcp_tool,omitempty"`
    MCPArgs   map[string]any `json:"mcp_args,omitempty"`
}
```

---

## Brain プロンプトへの MCP スキーマ注入

`buildSystemPrompt()` に MCP ツール情報セクションを追加する。
MCP サーバーから取得したツールスキーマを整形して Brain のシステムプロンプトに埋め込む:

```
MCP TOOLS:
Server: playwright
  - browser_navigate(url: string): Navigate to URL
  - browser_click(element: string, ref: string): Click an element
  - browser_type(element: string, ref: string, text: string): Type text
  - browser_snapshot(): Get page accessibility snapshot

To use MCP tools, respond with:
{
  "thought": "...",
  "action": "call_mcp",
  "mcp_server": "playwright",
  "mcp_tool": "browser_navigate",
  "mcp_args": {"url": "http://target/login"}
}
```

---

## Agent Loop のディスパッチ

```go
case schema.ActionCallMCP:
    l.callMCP(ctx, action)
    l.evaluateResult()
```

`callMCP()` の処理フロー:

1. `MCPManager.CallTool()` を呼び出し
2. 結果を ToolResult 互換形式に変換
3. TUI にログ出力（source: SourceTool）
4. Brain への次回入力に結果を含める

---

## 承認ゲート

MCP サーバー設定の `proposal_required` フィールドで制御する:

- **false**: Brain が `call_mcp` で直接実行（ブラウザ操作等）
- **true**: Brain が `propose` アクション + MCP 情報で提案 → ユーザー承認後に実行（API 課金あり等）

---

## main.go の起動フロー変更

```go
mcpMgr, err := mcp.NewManager("config/mcp.yaml")
if err != nil { /* MCP なしで続行（警告ログ出力） */ }
if mcpMgr != nil {
    mcpMgr.StartAll(ctx)
    defer mcpMgr.Close()
    brainCfg.MCPTools = mcpMgr.ListAllTools()
}
teamCfg.MCPManager = mcpMgr
```

MCP 設定ファイルが存在しない場合やパースに失敗した場合は、MCP 機能なしで pentecter を起動する。
これにより MCP は完全にオプショナルな拡張として機能する。

---

## 関連ファイル

| ファイル | 関連 |
|---------|------|
| `docs/architecture_design/design-philosophy.md` | MCP との組み合わせセクション |
| `docs/architecture_design/execution-model.md` | コマンド実行モデル |
| `pkg/schema/action.go` | Action 型定義 |
| `internal/brain/brain.go` | Brain インターフェース |
| `internal/brain/prompt.go` | システムプロンプト構築 |
| `internal/agent/loop.go` | Agent Loop ディスパッチ |
| `cmd/pentecter/main.go` | 起動フロー |
