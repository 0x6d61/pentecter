# 設定システム設計

## 概要

pentecter は複数の YAML 設定ファイルで外部ツール・ナレッジベース・安全パターンを管理する。
全設定ファイルは `config/` ディレクトリに配置され、`${VAR}` 形式の環境変数展開をサポートする。
ファイルが存在しない場合はエラーにせず、デフォルト値またはスキップで起動を継続する（graceful skip）。

---

## 設定ファイル一覧

| ファイル | パッケージ | 用途 |
|---------|-----------|------|
| `config/mcp.yaml` | `internal/mcp` | MCP サーバー定義 |
| `config/knowledge.yaml` | `internal/knowledge` | ナレッジベース定義 |
| `config/blacklist.yaml` | `internal/tools` | 危険コマンドのブラックリスト |
| `.env` | (godotenv) | 環境変数ファイル |

---

## main.go での読み込み順序

```go
// cmd/pentecter/main.go

// 1. .env ファイル読み込み（存在しなければ無視）
_ = godotenv.Load()

// 2. フラグ解析
flag.Parse()

// 3. ツールレジストリ（tools/*.yaml）
registry := tools.NewRegistry()
registry.LoadDir("tools")

// 4. MCP 設定
mcpMgr, mcpErr := mcp.NewManager("config/mcp.yaml")

// 5. Brain 設定 + MCP ツール注入
brainCfg, _ := brain.LoadConfig(...)
if mcpMgr != nil {
    mcpMgr.StartAll(ctx)
    // MCP ツールスキーマを brainCfg.MCPTools に追加
}

// 6. ブラックリスト
blacklist := loadBlacklist("config/blacklist.yaml")

// 7. スキル（skills/*.md）
skillsReg := skills.NewRegistry()
skillsReg.LoadDir("skills")

// 8. ナレッジベース
knowledgeCfg, _ := knowledge.LoadConfig("config/knowledge.yaml")

// 9. メモリストア
memoryStore := memory.NewStore("memory")
```

---

## config/mcp.yaml — MCP サーバー設定

### YAML スキーマ

```yaml
servers:
  - name: <string>              # サーバー識別名（Brain が参照）
    command: <string>            # 起動コマンド（${VAR} 展開対応）
    args: [<string>, ...]        # コマンドライン引数（${VAR} 展開対応）
    env:                         # 環境変数（${VAR} 展開対応）
      KEY: "value"
    proposal_required: <bool>    # true: ツール呼び出し前にユーザー承認が必要
```

### Go 構造体

```go
// internal/mcp/types.go

type MCPConfig struct {
    Servers []ServerConfig `yaml:"servers"`
}

type ServerConfig struct {
    Name             string            `yaml:"name"`
    Command          string            `yaml:"command"`
    Args             []string          `yaml:"args"`
    Env              map[string]string `yaml:"env,omitempty"`
    ProposalRequired *bool             `yaml:"proposal_required,omitempty"`
}
```

### 実例

```yaml
servers:
  - name: hacktricks
    command: node
    args: ["${HOME}/hacktricks-mcp-server/dist/index.js"]
    env: {}
    proposal_required: false
```

### 読み込み処理

```go
// internal/mcp/config.go

func LoadConfig(path string) (*MCPConfig, error) {
    // 1. ファイル読み込み（存在しない → nil, nil）
    // 2. YAML パース
    // 3. 環境変数展開（env, args, command の ${VAR}）
}
```

`mcp.NewManager()` が内部で `LoadConfig()` を呼び出す。

---

## config/knowledge.yaml — ナレッジベース設定

### YAML スキーマ

```yaml
knowledge:
  - name: <string>    # ナレッジベース識別名
    path: <string>    # コンテンツディレクトリパス（${VAR} 展開対応）
```

### Go 構造体

```go
// internal/knowledge/config.go

type KnowledgeConfig struct {
    Knowledge []KnowledgeEntry `yaml:"knowledge"`
}

type KnowledgeEntry struct {
    Name string `yaml:"name"`
    Path string `yaml:"path"`
}
```

### 実例

```yaml
knowledge:
  - name: hacktricks
    path: "${HOME}/hacktricks/src"
```

### 読み込み処理

```go
// internal/knowledge/config.go

func LoadConfig(path string) (*KnowledgeConfig, error) {
    // 1. ファイル読み込み（存在しない → nil, nil）
    // 2. YAML パース
    // 3. 環境変数展開（path の ${VAR}）
}
```

main.go では最初のエントリのみを使用（将来的に複数対応可能）:

```go
if knowledgeCfg != nil && len(knowledgeCfg.Knowledge) > 0 {
    ks := knowledge.NewStore(knowledgeCfg.Knowledge[0].Path)
    // パスが存在しなければ ks は nil
}
```

---

## config/blacklist.yaml — ブラックリスト設定

### YAML スキーマ

```yaml
patterns:
  - '<正規表現>'    # Go regexp 準拠
  - '<正規表現>'
```

### 実例

```yaml
patterns:
  # ファイルシステムの破壊的操作
  - 'rm\s+-rf\s+/'
  - 'rm\s+--no-preserve-root'
  - 'dd\s+if='
  - 'mkfs'
  - 'fdisk'
  - 'parted'

  # デバイスへの直接書き込み
  - '>\s*/dev/sd'
  - '>\s*/dev/nvme'
  - '>\s*/dev/hd'

  # システム停止
  - '\bshutdown\b'
  - '\breboot\b'
  - '\binit\s+0\b'
  - '\bpoweroff\b'

  # Windows 固有
  - 'format\s+[a-z]:'
  - 'del\s+/[sq]'

  # フォークボム
  - ':\(\)\{.*\|.*:.*\}'
```

### 読み込み処理

`loadBlacklist()` は `cmd/pentecter/main.go` に直接実装されている（専用パッケージなし）:

```go
func loadBlacklist(path string) *tools.Blacklist {
    data, err := os.ReadFile(path)
    if err != nil {
        // ファイルが存在しない場合はデフォルトパターンを使用
        return tools.NewBlacklist([]string{
            `rm\s+-rf\s+/`,
            `dd\s+if=`,
            `mkfs`,
            `\bshutdown\b`,
            `\breboot\b`,
        })
    }
    var cfg struct {
        Patterns []string `yaml:"patterns"`
    }
    yaml.Unmarshal(data, &cfg)
    return tools.NewBlacklist(cfg.Patterns)
}
```

### デフォルトパターン（ファイル不在時）

ファイルが存在しない場合、以下の最小限のパターンがハードコードされる:

| パターン | 防止する操作 |
|---------|------------|
| `rm\s+-rf\s+/` | ルートディレクトリの再帰削除 |
| `dd\s+if=` | ディスクイメージの書き込み |
| `mkfs` | ファイルシステムの作成（フォーマット） |
| `\bshutdown\b` | システムシャットダウン |
| `\breboot\b` | システム再起動 |

---

## ${VAR} 環境変数展開パターン

### 共通実装

`mcp` パッケージと `knowledge` パッケージで同一パターンの実装が使われている:

```go
var envVarPattern = regexp.MustCompile(`\$\{([^}]+)\}`)

func expandEnvString(s string) string {
    return envVarPattern.ReplaceAllStringFunc(s, func(match string) string {
        varName := match[2 : len(match)-1]  // ${VAR} → VAR
        return os.Getenv(varName)
    })
}
```

### 展開ルール

- `${HOME}` → `os.Getenv("HOME")` の値
- 未定義の環境変数 → 空文字列に展開（エラーにならない）
- `$HOME`（波括弧なし）→ 展開されない（`${...}` 形式のみ対応）

### 展開対象フィールド

| 設定ファイル | 展開対象 |
|------------|---------|
| `config/mcp.yaml` | `command`, `args[]`, `env{}` の値 |
| `config/knowledge.yaml` | `path` |

---

## Graceful Skip 動作

全設定ファイルの読み込みで共通する設計方針: **ファイルが存在しない場合はエラーにせず、nil を返して処理をスキップする。**

### 各パッケージの動作

| パッケージ | ファイル不在時 | 読み込みエラー時 |
|-----------|--------------|----------------|
| `mcp.LoadConfig()` | `nil, nil` を返す | エラーを返す |
| `knowledge.LoadConfig()` | `nil, nil` を返す | エラーを返す |
| `loadBlacklist()` | デフォルトパターンで `Blacklist` を生成 | デフォルトで `Blacklist` を生成 |
| `godotenv.Load()` | エラーを無視 (`_ =`) | エラーを無視 |

### 実装パターン

```go
// mcp/config.go, knowledge/config.go 共通パターン
data, err := os.ReadFile(path)
if err != nil {
    if errors.Is(err, os.ErrNotExist) {
        return nil, nil  // graceful skip
    }
    return nil, fmt.Errorf("...") // その他のエラーは報告
}
```

### main.go での処理

```go
// MCP: nil でも起動継続
mcpMgr, mcpErr := mcp.NewManager("config/mcp.yaml")
if mcpErr != nil {
    fmt.Fprintf(os.Stderr, "MCP config warning: %v\n", mcpErr)  // 警告のみ
}

// Knowledge: nil でも起動継続
knowledgeCfg, kErr := knowledge.LoadConfig("config/knowledge.yaml")
if kErr != nil {
    fmt.Fprintf(os.Stderr, "Knowledge config warning: %v\n", kErr)  // 警告のみ
}
```

---

## .env ファイル

### 読み込み

```go
_ = godotenv.Load()  // .env が存在しなくても無視
```

`github.com/joho/godotenv` で `.env` ファイルから環境変数を読み込む。
これにより、YAML 設定ファイル内の `${VAR}` が正しく展開される。

### 主要な環境変数

| 変数 | 用途 |
|------|------|
| `ANTHROPIC_API_KEY` | Anthropic API キー |
| `CLAUDE_CODE_OAUTH_TOKEN` | Claude Code OAuth トークン |
| `OPENAI_API_KEY` | OpenAI API キー |
| `OLLAMA_BASE_URL` | Ollama サーバー URL |
| `OLLAMA_MODEL` | Ollama モデル名 |
| `SUBAGENT_MODEL` | サブエージェント用モデル名（オプション） |
| `SUBAGENT_PROVIDER` | サブエージェント用プロバイダー（オプション） |
| `HOME` | YAML 内の `${HOME}` 展開に使用 |

---

## 関連ファイル

| ファイル | 役割 |
|---------|------|
| `config/mcp.yaml` | MCP サーバー設定 |
| `config/knowledge.yaml` | ナレッジベース設定 |
| `config/blacklist.yaml` | コマンドブラックリスト |
| `internal/mcp/config.go` | MCP 設定読み込み + `${VAR}` 展開 |
| `internal/mcp/types.go` | `MCPConfig`, `ServerConfig` 構造体 |
| `internal/knowledge/config.go` | ナレッジ設定読み込み + `${VAR}` 展開 |
| `cmd/pentecter/main.go` | 設定読み込みオーケストレーション、`loadBlacklist()` |
