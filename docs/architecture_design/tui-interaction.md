# TUI インタラクション設計

## 概要

TUI のユーザー操作・コマンド・選択UI の設計。

## コマンド一覧

| コマンド | 説明 |
|---------|------|
| `/model` | LLM プロバイダー/モデルの選択・切り替え |
| `/approve` | Auto-approve の ON/OFF 切り替え |
| `/target <host>` | ターゲットの追加 |
| `<IP>` | IP アドレス入力でターゲット追加 |
| 自然言語 | AI エージェントへの指示 |

## 選択UI

`/model` や `/approve` を引数なしで実行した場合、テキスト入力ではなく対話的な選択UIを表示する。

### 動作

```
> /approve

Auto-approve (current: OFF):
  ● ON — auto-approve all commands
    OFF — require approval
[↑↓] Move  [Enter] Select  [Esc] Cancel
```

### キー操作

| キー | 動作 |
|------|------|
| `↑` / `↓` | 選択肢を移動 |
| `Enter` | 選択を確定し、コールバックを実行 |
| `Esc` | キャンセルして通常モードに戻る |

### 実装

- `Model.inputMode` で `InputNormal` / `InputSelect` を管理
- `InputSelect` 時はテキスト入力を無効化し、選択UI を input bar に描画
- `showSelect(title, options, callback)` メソッドで選択UIを起動
- 後方互換: `/approve on` `/approve off` のテキスト指定も引き続き動作

## コマンドサジェスト

入力フィールドで `/` を入力すると、利用可能なコマンドをオートコンプリート候補として表示。
右矢印キーでサジェストを確定。

登録済みサジェスト: `/model`, `/approve`, `/target`

## Proposal（承認ゲート）

承認が必要なコマンドは PROPOSAL ボックスとして表示:

| キー | 動作 |
|------|------|
| `y` | 承認 → コマンドを実行 |
| `n` | 拒否 → Brain に「ユーザーが拒否した」と伝える |
| `e` | 編集 → コマンドを input bar にコピーして編集可能にする |

## Agent イベントと表示

### イベントタイプ一覧

Agent Loop から TUI へ送信されるイベントの全種別:

| イベントタイプ | 値 | 説明 |
|---------------|-----|------|
| `EventLog` | `"log"` | 通常のログ行（AI の思考・ツール出力・システムメッセージ） |
| `EventProposal` | `"proposal"` | Brain がエクスプロイト等の重要アクションを提案 |
| `EventComplete` | `"complete"` | ターゲットのアセスメントが完了 |
| `EventError` | `"error"` | リカバリー不能なエラーが発生 |
| `EventAddTarget` | `"add_target"` | 横展開で新ターゲットを追加 |
| `EventStalled` | `"stalled"` | 連続失敗でユーザーの方針指示を待機 |
| `EventTurnStart` | `"turn_start"` | Brain 思考サイクルの開始 |
| `EventCommandResult` | `"command_result"` | コマンド実行結果のサマリー |

### Event 構造体のフィールド

```go
type Event struct {
    TargetID   int       // どのターゲットのイベントか（TUI のルーティング用）
    Type       EventType
    Source     LogSource // EventLog 時に使用
    Message    string
    Proposal   *Proposal // EventProposal 時に使用
    NewHost    string    // EventAddTarget 時に使用
    TurnNumber int       // EventTurnStart 時のターン番号
    ExitCode   int       // EventCommandResult 時の exit code
}
```

### LogEntry の拡張フィールド

セッションログの各エントリ（`LogEntry`）は、通常のログ情報に加えて以下のフィールドを持つ:

```go
type LogEntry struct {
    Time       time.Time
    Source     LogSource
    Message    string
    Type       EventType // "turn_start", "command_result", or "" (通常ログ)
    TurnNumber int       // EventTurnStart 時のターン番号
    ExitCode   int       // EventCommandResult 時の exit code
}
```

| フィールド | 使用条件 | 説明 |
|-----------|---------|------|
| `Type` | 常に設定可 | `EventTurnStart` または `EventCommandResult` の場合に特殊表示を行う。空文字は通常ログ |
| `TurnNumber` | `Type == EventTurnStart` | ターン区切り表示に使用するターン番号（1始まり） |
| `ExitCode` | `Type == EventCommandResult` | コマンド結果サマリーの色分けに使用 |

### ターン区切りの表示仕様

`EventTurnStart` イベントを受信すると、セッションログにターン区切り線を描画する:

```
───────────── Turn 3 ─────────────
```

- 区切り線は `─` 記号でビューポート幅いっぱいに描画
- ターン番号は中央に配置
- スタイル: 薄い色（`colorMuted`）で表示し、通常のログとの視覚的区別を明確にする

### コマンド結果サマリーの表示仕様

`EventCommandResult` イベントを受信すると、コマンド実行結果を1行サマリーで表示する:

- **成功時（exit code == 0）**: 緑色で表示
  ```
  ✓ exit 0 (42 lines)
  ```
- **失敗時（exit code != 0）**: 赤色太字で表示
  ```
  ✗ exit 1: Connection refused
  ```

サマリーの生成ロジック（`buildCommandSummary()`）:
- 成功時: exit code と出力行数を表示
- 失敗時: exit code と出力の1行目（最大80文字、超過分は `...` で切り捨て）を表示

## 関連ファイル

- `internal/tui/model.go` — Model struct、InputMode、SelectOption
- `internal/tui/update.go` — コマンド処理、選択UI のキー操作
- `internal/tui/view.go` — 選択UI のレンダリング、ターン区切り・コマンド結果サマリー
- `internal/agent/event.go` — EventType 定義、Event 構造体
- `internal/agent/target.go` — LogEntry 構造体（Type, TurnNumber, ExitCode フィールド）
