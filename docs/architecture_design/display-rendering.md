# 表示レンダリング設計

## 概要

pentecter の TUI は **DisplayBlock** を基本単位としたブロックベースレンダリングを採用している。
Agent ループから送信されるイベントが `DisplayBlock` に変換され、`renderBlocks()` で変換され、各ブロックは完了時に`rl.Stdout()` 経由で stdout に直接出力される。

## DisplayBlock モデル

### 定義

```go
// internal/agent/display.go

type BlockType int

const (
    BlockCommand   BlockType = iota // コマンド + 折りたたみ可能な出力
    BlockThinking                   // スピナー → "Completed in Xs"
    BlockAIMessage                  // Markdown レンダリングされた AI レスポンス
    BlockMemory                     // 重要度 + タイトル（発見事項）
    BlockSubTask                    // スピナー → ゴール + 所要時間
    BlockUserInput                  // ハイライト付きユーザー入力
    BlockSystem                     // システムメッセージ
)
```

### フィールド構成

`DisplayBlock` は全ブロック型のフィールドを包含する共用構造体。各ブロック型は一部のフィールドのみを使用する。

```go
type DisplayBlock struct {
    Type      BlockType
    CreatedAt time.Time

    // BlockCommand 用
    Command   string
    Output    []string
    ExitCode  int
    Completed bool
    Duration  time.Duration

    // BlockThinking 用
    ThoughtPreview string
    ThinkingDone   bool
    ThinkDuration  time.Duration

    // BlockAIMessage 用
    Message string

    // BlockMemory 用
    Severity string
    Title    string

    // BlockSubTask 用
    TaskID       string
    TaskGoal     string
    TaskDone     bool
    TaskDuration time.Duration

    // BlockUserInput 用
    UserText string

    // BlockSystem 用
    SystemMsg string
}
```

### ファクトリ関数

各ブロック型に対応するファクトリ関数が用意されている:

| 関数 | 用途 |
|------|------|
| `NewCommandBlock(command)` | コマンド実行ブロック |
| `NewThinkingBlock()` | 思考中ブロック |
| `NewAIMessageBlock(message)` | AI メッセージブロック |
| `NewMemoryBlock(severity, title)` | メモリ/発見事項ブロック |
| `NewSubTaskBlock(taskID, goal)` | サブタスクブロック |
| `NewUserInputBlock(text)` | ユーザー入力ブロック |
| `NewSystemBlock(message)` | システムメッセージブロック |

全ファクトリは `CreatedAt` を `time.Now()` で自動設定する。

---

## レンダリングパイプライン

### 全体フロー

```
Target.Blocks []*DisplayBlock
       │
       ▼
renderBlocks(blocks, width, expanded, spinnerFrame)
       │
       ├── BlockCommand  → renderCommandBlock(b, width, expanded)
       ├── BlockThinking → renderThinkingBlock(b, spinnerFrame)
       ├── BlockAIMessage → renderAIMessageBlock(b, width)
       ├── BlockMemory   → renderMemoryBlock(b)
       ├── BlockSubTask  → renderSubTaskBlock(b, width, spinnerFrame)
       ├── BlockUserInput → renderUserInputBlock(b, width)
       └── BlockSystem   → renderSystemBlock(b)
       │
       ▼
string (ビューポートコンテンツ)
```

### rebuildViewport() のトリガー

`rebuildViewport()` は以下のタイミングで呼び出される:

1. **ウィンドウリサイズ** (`tea.WindowSizeMsg`)
2. **Agent イベント受信** (`handleAgentEvent` で表示中ターゲットのイベント時)
3. **スピナーティック** (`spinner.TickMsg` で再描画)
4. **ユーザー操作** (ターゲット切り替え、折りたたみ切り替え、入力送信等)

```go
func (m *Model) rebuildViewport() {
    // 1. アクティブターゲットの Blocks を取得
    // 2. renderBlocks() でブロック群を文字列化
    // 3. Proposal があればビューポート末尾に追加
    // 4. viewport.SetContent() で設定
    // 5. 底付近にいた場合は自動スクロール
}
```

### 自動スクロール

`rebuildViewport()` は SetContent 前に `viewport.AtBottom()` をチェックし、ユーザーが底付近にいた場合のみ自動スクロールする。手動でスクロールアップしている場合は位置を維持する。

---

## 各ブロック型の表示フォーマット

### BlockCommand — コマンド実行

```
● nmap -sV -sC 10.0.0.5
  ⎿  Starting Nmap 7.94 ...
     PORT   STATE SERVICE VERSION
     22/tcp open  ssh     OpenSSH 8.9
     … +42 lines (ctrl+o)
```

- **ヘッダー**: `● ` + コマンド文字列（`colorPrimary` = シアン、太字）
- **出力**: 1行目は `⎿  ` プレフィックス、2行目以降は `     ` (5スペース) プレフィックス
- **出力色**: `#AAAAAA`（グレー）

### BlockThinking — 思考中

処理中:
```
⠋ Thinking...
```

完了:
```
✻ Completed in 3s
```

- **処理中**: スピナーフレーム + " Thinking..."（`colorSecondary` = 紫）
- **完了**: `✻ Completed in Xs`（`colorSecondary` = 紫）
- 時間フォーマット: `<1s`, `12s`, `1m23s`

### BlockAIMessage — AI レスポンス

glamour でマークダウンレンダリングされたテキスト。フォールバック時はプレーンテキスト。

### BlockMemory — 発見事項

```
📝 [HIGH] SQL injection found in login form
```

- `📝 [SEVERITY] title` フォーマット（`colorWarning` = 黄色）

### BlockSubTask — サブタスク

処理中:
```
⠋ Running port scan on all TCP ports
```

完了:
```
̶R̶u̶n̶n̶i̶n̶g̶ ̶p̶o̶r̶t̶ ̶s̶c̶a̶n̶ ✓ 45s
```

- **処理中**: スピナーフレーム + ゴールテキスト（`colorPrimary` = シアン）
- **完了**: ゴールに取り消し線（`colorMuted`） + `✓ Xs`（`colorSuccess` = 緑）
- 幅に収まらない場合はゴールを折り返し、チェックマークは最終行に付与

### BlockUserInput — ユーザー入力

```
> scan all ports please
```

- `> ` + テキスト
- スタイル: 背景色 `#1A1A2E`、文字色 `colorSuccess`（緑）、太字、左右パディング 1

### BlockSystem — システムメッセージ

```
Agent started: 10.0.0.5
```

- プレーンテキスト（`colorMuted` = 薄灰色）

---

## 折りたたみ（Folding）動作

### コマンド出力の折りたたみ

```go
const cmdFoldThreshold = 5   // この行数を超えると折りたたみ
const previewLines = 3       // 折りたたみ時に表示する先頭行数
```

- **デフォルト**: 折りたたみ状態（`expanded = false`）
- 出力が **5行を超える** 場合、先頭 **3行** のみ表示
- 残りは `… +N lines (ctrl+o)` インジケータで表示

### 展開/折りたたみ切り替え

- **Ctrl+O** でグローバルに全ブロックの折りたたみを切り替え（`logsExpanded` トグル）
- どのペインにフォーカスがあっても動作する

### 折りたたみインジケータスタイル

```go
var foldIndicatorStyle = lipgloss.NewStyle().Foreground(colorMuted).Italic(true)
```

表示例: `     … +42 lines (ctrl+o)`

---

## スピナーアニメーション

### 動作原理

1. **開始**: `EventThinkStart` または `EventSubTaskStart` で `m.spinning = true` → `m.spinner.Tick` を返す
2. **ティック**: `spinner.TickMsg` で `m.spinner.Update()` → `rebuildViewport()` で再描画
3. **停止**: 完了イベント後に `hasActiveSpinner()` で未完了ブロックをチェック → なければ `m.spinning = false`

```go
func (m *Model) hasActiveSpinner() bool {
    // アクティブターゲットの Blocks を走査
    // BlockThinking で ThinkingDone == false → true
    // BlockSubTask で TaskDone == false → true
}
```

### スピナーフレーム

Bubble Tea の `spinner.Model` が提供するフレーム（例: `⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏`）を `m.spinner.View()` で取得し、`renderBlocks()` の `spinnerFrame` 引数として渡す。

---

## glamour マークダウンレンダリング

### 実装

```go
func renderMarkdown(text string, width int) (string, error) {
    wrapWidth := width - 4  // glamour dark スタイルの左右マージン分
    if wrapWidth < 20 {
        wrapWidth = 20
    }
    r, err := glamour.NewTermRenderer(
        glamour.WithStylePath("dark"),
        glamour.WithWordWrap(wrapWidth),
    )
    // ...
}
```

### 設計判断

- **ダークスタイル固定**: TUI は常にダークターミナルで使用される想定のため `WithStylePath("dark")` を明示指定
- **`WithAutoStyle()` を不使用**: 非 TTY 環境（テスト・CI）で plain にフォールバックしてしまうため
- **幅調整**: glamour の dark スタイルは左右マージン（各2文字 = 計4文字）を追加するため、渡す幅から 4 を引く
- **フォールバック**: glamour レンダリング失敗時はプレーンテキスト + 改行で表示

---

## カラーパレット

`internal/tui/styles.go` で定義されるカラー定数:

| 変数 | 色コード | 用途 |
|------|---------|------|
| `colorPrimary` | `#00D7FF` (シアン) | フォーカス、AI、コマンドヘッダー |
| `colorSecondary` | `#AF87FF` (紫) | AI ソースラベル、思考ブロック |
| `colorSuccess` | `#87FF5F` (緑) | PWNED、ユーザー入力、サブタスク完了 |
| `colorWarning` | `#FFD700` (黄) | PAUSED、Proposal、メモリブロック |
| `colorDanger` | `#FF5555` (赤) | FAILED |
| `colorMuted` | `#555577` (薄灰) | タイムスタンプ、ヒント、折りたたみ、システムメッセージ |
| `colorBorder` | `#333355` | ペインボーダー（非フォーカス） |
| `colorBorderActive` | `#00D7FF` | ペインボーダー（フォーカス） |
| `colorTitle` | `#FFFFFF` | ペインタイトル |

---

## 関連ファイル

| ファイル | 役割 |
|---------|------|
| `internal/agent/display.go` | BlockType, DisplayBlock 定義、ファクトリ関数 |
| `internal/tui/render.go` | 各ブロック型のレンダリング関数、`renderBlocks()` |
| `internal/tui/styles.go` | カラーパレット、lipgloss スタイル定義 |
| `internal/tui/model.go` | `rebuildViewport()` — ブロック→ビューポートの統合 |
| `internal/tui/update.go` | `handleAgentEvent()` — イベント→ブロック変換 |
