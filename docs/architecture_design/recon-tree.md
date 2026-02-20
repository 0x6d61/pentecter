# Recon Tree — 構造的偵察制御

## 課題

現状の ASSESSMENT WORKFLOW はプロンプトで偵察手順を指示しているが、LLM の判断に依存するため：
- vhost を発見しても endpoint 列挙をスキップする
- 一部の endpoint だけ param fuzz して残りを飛ばす
- ffuf の再帰的深堀りを途中でやめる
- nmap 結果を LLM が要約すると情報が落ちる（「メモうっすい」問題）

**偵察 = 成功率**。漏れを構造的に防ぐ必要がある。

## 設計方針

- **ReconTree**: ターゲットの偵察状態をツリー構造で管理するタスクキュー
- **生出力はファイル保存**: nmap/ffuf/curl の出力はディスクに保存、ReconTree はファイルパスを参照しない（LLM が必要時に `cat` で読む）
- **pending がある限り RECON を抜けられない**: コードレベルで強制
- **LLM は Tree が指示するタスクを実行するだけ**: 「何をスキャンするか」の判断を LLM に委ねない

## データ構造

```go
type TaskStatus int

const (
    StatusPending    TaskStatus = iota
    StatusInProgress
    StatusComplete
)

type ReconNode struct {
    Host         string       // "10.10.11.100" or "dev.example.com" (vhost)
    Port         int          // 80, 443, 22... (0 = endpoint node)
    Service      string       // "http", "ssh", "smb"
    Banner       string       // "Apache 2.4.49", "OpenSSH 8.2"
    Path         string       // "/", "/api", "/api/v1" (endpoint nodes only)

    // タスクステータス（ノードタイプによって使うフィールドが異なる）
    EndpointEnum TaskStatus   // ffuf でサブディレクトリ列挙
    ParamFuzz    TaskStatus   // ffuf でパラメータ発見
    Profiling    TaskStatus   // curl でレスポンス特性把握
    VhostDiscov  TaskStatus   // ffuf で仮想ホスト探索

    Children     []*ReconNode
}
```

### ノードタイプの区別

| 条件 | ノードタイプ | 使うフィールド |
|------|------------|--------------|
| `Port > 0 && Service == "http/https"` | HTTP ポート | VhostDiscov, EndpointEnum, ParamFuzz, Profiling + Children |
| `Port > 0 && Service != "http"` | 非 HTTP ポート | なし（葉ノード、バナー情報のみ） |
| `Port == 0 && Path != ""` | Endpoint | EndpointEnum, ParamFuzz, Profiling + Children |
| `Host != root && Port == 0 && Path == ""` | Vhost ルート | VhostDiscov, EndpointEnum + Children |

## ツリー構造の例

```
10.10.11.100 (root)
├── 22/ssh OpenSSH 8.2                    ← nmap から（葉ノード）
├── 80/http Apache 2.4.49                 ← nmap から
│   ├── vhost_discovery: ✅
│   ├── endpoint_enum(/): ✅
│   ├── param_fuzz(/): ✅
│   ├── profiling(/): ✅
│   ├── /api
│   │   ├── endpoint_enum: ✅
│   │   ├── param_fuzz: ⏳               ← endpoint 発見時に自動追加
│   │   ├── profiling: ⏳
│   │   └── /api/v1
│   │       ├── endpoint_enum: ✅ (子なし → 自動完了)
│   │       ├── param_fuzz: ⏳
│   │       ├── profiling: ⏳
│   │       └── /api/v1/user
│   │           ├── endpoint_enum: ✅ (子なし)
│   │           ├── param_fuzz: ⏳
│   │           └── profiling: ⏳
│   ├── /login
│   │   ├── endpoint_enum: ✅ (子なし)
│   │   ├── param_fuzz: ✅
│   │   └── profiling: ✅
│   └── /admin
│       ├── endpoint_enum: ⏳
│       ├── param_fuzz: ⏳
│       └── profiling: ⏳
├── 445/smb Samba 4.6.2                   ← nmap から（葉ノード）
│
└── [vhost] dev.example.com → port 80
    ├── vhost_discovery: ⏳               ← サブ vhost チェック
    ├── endpoint_enum(/): ⏳
    └── (endpoints discovered later...)
```

## 自動タスク生成ルール

| イベント | Tree への効果 |
|----------|--------------|
| nmap が HTTP ポート発見 | ポートノード追加 + `VhostDiscov: pending` + `EndpointEnum: pending` |
| nmap が非 HTTP ポート発見 | ポートノード追加（葉、タスクなし） |
| ffuf (dir) が endpoint 発見 | 子ノード追加 + `EndpointEnum: pending` + `ParamFuzz: pending` + `Profiling: pending` |
| ffuf (dir) が結果ゼロ | そのノードの `EndpointEnum → complete` |
| ffuf (vhost) が vhost 発見 | vhost ノード追加 + `VhostDiscov: pending` + `EndpointEnum: pending` |
| ffuf (vhost) が結果ゼロ | そのノードの `VhostDiscov → complete` |
| ffuf (param) 完了 | そのノードの `ParamFuzz → complete` |
| curl profiling 完了 | そのノードの `Profiling → complete` |

## 生出力のファイル保存

ツール出力は ReconTree に含めず、既存の memory ディレクトリ配下に保存：

```
memory/<host>/
├── vulnerability.txt          ← 既存（LLM の分析結果）
├── credential.txt             ← 既存
├── artifact.txt               ← 既存
├── finding.txt                ← 既存
└── raw/                       ← 新規（ツール生出力）
    ├── nmap.txt
    ├── ffuf_dir_80_root.json
    ├── ffuf_dir_80_api.json
    ├── ffuf_dir_80_api_v1.json
    ├── ffuf_vhost_80.json
    ├── ffuf_param_80_login.json
    └── curl_80_login.txt
```

- 既存の `memory/<host>/` 構造と一貫性がある
- `.gitignore` で `memory/*` は除外済み
- セッション終了後も残る（`/tmp/` と違って消えない）
- LLM が参照したいときは `cat memory/<host>/raw/nmap.txt` で読める
- コンテキストに全部詰めない — 必要なときだけ読む

## コアフロー

```
1. Agent が nmap/ffuf/curl を実行
       ↓
2. evaluateResult() がツール出力を検知
       ↓
3. Parser がツール出力から結果を抽出
   - nmap -oX → encoding/xml でパース → ポートノード生成
   - ffuf -of json → JSON パース → endpoint/vhost ノード生成
   - curl → exit code + ヘッダで profiling 完了判定
       ↓
4. ReconTree に子ノード追加（pending タスク自動生成）
       ↓
5. 次の LLM 呼び出し時、プロンプトに pending タスクを注入:
   "RECON QUEUE (3 pending):
    1. endpoint_enum: /admin on 10.10.11.100:80
    2. param_fuzz: /api/v1 on 10.10.11.100:80
    3. profiling: /api/v1/user on 10.10.11.100:80"
       ↓
6. LLM は Queue の先頭を実行するだけ
       ↓
7. pending が 0 になったら → RECON 完了 → ANALYZE フェーズへ進行許可
```

## RECON 完了判定

```go
func (t *ReconTree) HasPending() bool {
    // ツリーを走査して pending ノードがあるか確認
    return t.countPending() > 0
}

func (t *ReconTree) NextPending() *ReconNode {
    // DFS で最初の pending タスクを返す
    // 優先順位: endpoint_enum > param_fuzz > profiling > vhost_discovery
}
```

`HasPending() == true` の間は、`evaluateResult()` が RECON フェーズを強制。
LLM が `think` や `memory` で ANALYZE に進もうとしても、プロンプトに
「RECON QUEUE に pending タスクがあります。先にこれを実行してください」と注入。

## プロンプト注入フォーマット

```
RECON STATUS:
  Ports: 22/ssh, 80/http, 445/smb (3 discovered)
  Endpoints: 8 discovered, 5 profiled
  Vhosts: 1 discovered (dev.example.com)
  Parameters: 3 endpoints fuzzed

RECON QUEUE (3 pending):
  1. [endpoint_enum] /admin on 10.10.11.100:80
     → ffuf -w /usr/share/wordlists/dirb/common.txt -u http://10.10.11.100/admin/FUZZ
  2. [param_fuzz] /api/v1 on 10.10.11.100:80
     → ffuf -w burp-parameter-names.txt -u "http://10.10.11.100/api/v1?FUZZ=value" -fs <size>
  3. [profiling] /api/v1/user on 10.10.11.100:80
     → curl -ik http://10.10.11.100/api/v1/user

Execute the next pending task. Do NOT skip to ANALYZE while tasks remain.
```

コマンドまで生成してあげることで、LLM は JSON を返すだけ。

## 並列制御

偵察タスクを非同期（spawn_task）で実行する場合、同時実行数を制限しないと
ターゲットに対する DoS になりうる。ユーザーが設定可能な並列数制御を導入する。

### 設定

```yaml
# config/config.yaml
recon:
  max_parallel: 2    # 同時実行する偵察タスクの最大数（デフォルト: 2）
```

```go
// config.go に追加
type ReconConfig struct {
    MaxParallel int `yaml:"max_parallel"`
}

type AppConfig struct {
    Knowledge []KnowledgeEntry `yaml:"knowledge"`
    Blacklist []string         `yaml:"blacklist"`
    Recon     ReconConfig      `yaml:"recon"`
}
```

デフォルト値: `max_parallel = 2`（未設定時）

### ReconTree での制御

```go
type ReconTree struct {
    Root        *ReconNode
    MaxParallel int          // config から取得
    active      int          // 現在実行中のタスク数
}

func (t *ReconTree) NextBatch() []*ReconTask {
    available := t.MaxParallel - t.active
    if available <= 0 {
        return nil
    }
    return t.pickPending(available)
}
```

### プロンプトへの反映

```
RECON QUEUE (5 pending, 2 active, max_parallel=2):
  [active] endpoint_enum: /api on 10.10.11.100:80
  [active] param_fuzz: /login on 10.10.11.100:80
  [next]   profiling: /api/v1/user on 10.10.11.100:80
  [queued] endpoint_enum: /admin on 10.10.11.100:80
  [queued] vhost_discovery: dev.example.com
```

- `active` が `max_parallel` に達している → LLM に `wait` を指示
- タスク完了で空きが出たら → 次の pending を実行

## /recontree コマンド（TUI）

ユーザーが偵察の進捗をリアルタイムで確認できる TUI コマンド。
Log ペインにコードブロックとして出力する（glamour のレンダリング崩れを防止）。

### 表示例

```
/recontree

10.10.11.100
|-- 22/ssh OpenSSH 8.2
|-- 80/http Apache 2.4.49
|   |-- vhost_discovery [x]
|   |-- / [x][x][x] (enum/param/profile)
|   |-- /api [x][ ][ ]
|   |   +-- /api/v1 [x][ ][ ]
|   |       +-- /api/v1/user [x][ ][ ]
|   |-- /login [x][x][x]
|   +-- /admin [ ][ ][ ]
|-- 445/smb Samba 4.6.2
+-- [vhost] dev.example.com
    |-- vhost_discovery [ ]
    +-- / [ ][ ][ ]

Progress: 8/21 tasks complete (38%)
Active: 2/2 (max_parallel=2)
```

### 凡例

- `[x][x][x]` = endpoint_enum / param_fuzz / profiling すべて完了
- `[x][ ][ ]` = endpoint_enum 完了、param_fuzz と profiling が pending
- `[>]` = in_progress
- 非 HTTP ポートはステータスなし（バナー情報のみ）

### 表示の実装方針

- ASCII 文字のみ使用（`|-- +-- [ ] [x] [>]`）。絵文字は端末幅の不整合を起こすため不使用。
- `RenderTree() string` が返すテキストを TUI 側でコードブロック（`` ``` ``）で囲んで出力
- glamour のマークダウンレンダリングがコードブロック内はそのまま表示するため崩れない

### 実装

- `internal/agent/recon_tree.go` に `RenderTree() string` メソッドを追加
- `internal/tui/update.go` に `/recontree` コマンドハンドラを追加
- Log ペインにコードブロックとして出力

## 既存コードへの影響

| ファイル | 変更内容 |
|----------|---------|
| `internal/agent/recon_tree.go` | **新規**: ReconTree, ReconNode, パーサー, RenderTree |
| `internal/agent/recon_tree_test.go` | **新規**: ユニットテスト |
| `internal/agent/loop.go` | `evaluateResult()` にパーサー呼び出し + 並列制御追加 |
| `internal/brain/prompt.go` | `buildPrompt()` に RECON QUEUE 注入 |
| `internal/brain/prompt_test.go` | RECON QUEUE 注入テスト |
| `internal/config/config.go` | `ReconConfig` 追加（max_parallel） |
| `internal/config/config_test.go` | ReconConfig テスト追加 |
| `config/config.example.yaml` | `recon:` セクション追加 |
| `internal/tui/update.go` | `/recontree` コマンド追加 |

## 将来拡張

- 非 HTTP サービスの偵察タスク（SMB share_enum, FTP anon_check 等）
- Attack Graph との接続: ReconTree の profiling 結果 → Attack Graph の requires/provides
