# イベントシステム設計

## 概要

pentecter の Agent ループと TUI はイベント駆動で通信する。
Agent ループが `Event` を送信し、TUI の `handleAgentEvent()` がイベントを受信して `DisplayBlock` に変換する。
この単方向イベントストリームにより、Agent ループと TUI の責務が明確に分離される。

---

## EventType 定数

### 定義

```go
// internal/agent/event.go

type EventType string
```

### 一般イベント

| 定数 | 値 | 意味 |
|------|-----|------|
| `EventLog` | `"log"` | 通常のログ行。AI の思考・ツール出力・システムメッセージ |
| `EventProposal` | `"proposal"` | Brain がエクスプロイト等の重要アクションを提案 |
| `EventComplete` | `"complete"` | ターゲットのアセスメント完了 |
| `EventError` | `"error"` | リカバリー不能なエラー発生 |
| `EventAddTarget` | `"add_target"` | 横展開で新ターゲットを追加 |
| `EventStalled` | `"stalled"` | 連続失敗でユーザーの方針指示を待機 |
| `EventTurnStart` | `"turn_start"` | Brain 思考サイクルの開始 |
| `EventSubTaskLog` | `"subtask_log"` | サブタスクの出力ログ |
| `EventSubTaskComplete` | `"subtask_complete"` | サブタスクの完了通知 |

### ブロックベースレンダリングイベント

| 定数 | 値 | 意味 |
|------|-----|------|
| `EventThinkStart` | `"think_start"` | Brain.Think() の開始（スピナー開始） |
| `EventThinkDone` | `"think_done"` | Brain.Think() の完了 |
| `EventCmdStart` | `"cmd_start"` | コマンド実行の開始 |
| `EventCmdOutput` | `"cmd_output"` | コマンド出力の 1 行 |
| `EventCmdDone` | `"cmd_done"` | コマンド実行の完了 |
| `EventSubTaskStart` | `"subtask_start"` | サブタスク開始（スピナー表示） |

---

## Event 構造体

```go
type Event struct {
    TargetID   int           // どのターゲットのイベントか（TUI ルーティング用）
    Type       EventType
    Source     LogSource     // EventLog 時に使用（AI/TOOL/SYS/USER）
    Message    string
    Proposal   *Proposal     // EventProposal 時に使用
    NewHost    string        // EventAddTarget 時に使用
    TurnNumber int           // EventTurnStart 時のターン番号
    ExitCode   int           // EventCmdDone 時の exit code
    TaskID     string        // SubTask 関連イベント時の taskID
    Duration   time.Duration // EventThinkDone, EventCmdDone の所要時間
    OutputLine string        // EventCmdOutput の出力行
}
```

### フィールドの使用マッピング

| フィールド | 使用するイベント |
|-----------|----------------|
| `TargetID` | 全イベント（`emit()` で自動設定） |
| `Type` | 全イベント |
| `Source` | `EventLog` |
| `Message` | `EventLog`, `EventComplete`, `EventError`, `EventStalled`, `EventCmdStart`, `EventCmdDone`, `EventSubTaskStart` |
| `Proposal` | `EventProposal` |
| `NewHost` | `EventAddTarget` |
| `TurnNumber` | `EventTurnStart` |
| `ExitCode` | `EventCmdDone` |
| `TaskID` | `EventSubTaskStart`, `EventSubTaskLog`, `EventSubTaskComplete` |
| `Duration` | `EventThinkDone`, `EventCmdDone` |
| `OutputLine` | `EventCmdOutput` |

### LogSource

```go
type LogSource string

const (
    SourceAI     LogSource = "AI  "
    SourceTool   LogSource = "TOOL"
    SourceSystem LogSource = "SYS "
    SourceUser   LogSource = "USER"
)
```

---

## イベント送信: Loop.emit()

### 実装

```go
func (l *Loop) emit(e Event) {
    e.TargetID = l.target.ID    // TargetID を自動付与
    select {
    case l.events <- e:
    default:                     // チャネルが満杯の場合はドロップ
    }
}
```

### 設計判断

- **TargetID 自動付与**: 呼び出し側で TargetID を設定する必要がない
- **非ブロッキング送信**: チャネルが満杯（バッファ 512）の場合はイベントをドロップする。TUI がブロックしないことを保証
- **イベントチャネル**: `make(chan agent.Event, 512)` — main.go で生成

### チャネルルーティング

```
Agent Loop (goroutine)          TUI (main goroutine)
        │                              │
        │  l.emit(Event{...})          │
        │         │                    │
        ▼         ▼                    │
    events chan ──────────────► AgentEventCmd()
                                       │
                                       ▼
                               AgentEventMsg (tea.Msg)
                                       │
                                       ▼
                               handleAgentEvent(e)
```

1. Agent ループが `l.emit()` でイベントを送信
2. TUI 側では `AgentEventCmd()` が `tea.Cmd` としてチャネルを監視
3. イベント受信時に `AgentEventMsg` として Bubble Tea のメッセージキューに投入
4. `Update()` が `AgentEventMsg` を受信し `handleAgentEvent()` を呼び出す
5. 処理後、次のイベントを待つ `AgentEventCmd()` を再登録（非同期ループパターン）

---

## TUI handleAgentEvent — イベントからブロックへの変換

### 全体構造

```go
func (m *Model) handleAgentEvent(e agent.Event) tea.Cmd {
    // 1. TargetID でターゲットを特定（見つからなければアクティブターゲットにフォールバック）
    // 2. イベント型ごとに DisplayBlock を生成/更新
    // 3. syncListItems() + rebuildViewport() で表示更新
    // 4. スピナー開始が必要な場合は tea.Cmd を返す
}
```

### イベント → ブロック変換マッピング

| イベント | 生成/更新するブロック |
|---------|---------------------|
| `EventLog` (Source=AI) | `NewAIMessageBlock(e.Message)` 追加 |
| `EventLog` (Source=TOOL) | 未完了 `BlockCommand` があれば出力追記、なければ `NewCommandBlock()` 追加 |
| `EventLog` (Source=SYS) | `NewSystemBlock(e.Message)` 追加 |
| `EventLog` (Source=USER) | `NewUserInputBlock(e.Message)` 追加 |
| `EventProposal` | `target.SetProposal(e.Proposal)` — ブロックは追加しない |
| `EventComplete` | `NewSystemBlock("✅ " + e.Message)` 追加 |
| `EventError` | `NewSystemBlock("❌ " + e.Message)` 追加 |
| `EventAddTarget` | `m.addTarget(e.NewHost)` — 新ターゲット追加 |
| `EventStalled` | `NewSystemBlock("⚠ " + e.Message)` + 操作ガイドブロック追加 |
| `EventTurnStart` | ブロック追加なし（新 UI ではターンは暗黙的） |
| `EventThinkStart` | `NewThinkingBlock()` 追加 + スピナー開始 |
| `EventThinkDone` | 最後の `BlockThinking` を完了マーク |
| `EventCmdStart` | `NewCommandBlock(e.Message)` 追加 |
| `EventCmdOutput` | 最後の未完了 `BlockCommand` に `OutputLine` 追記 |
| `EventCmdDone` | 最後の `BlockCommand` を完了マーク（ExitCode, Duration 設定） |
| `EventSubTaskStart` | `NewSubTaskBlock(e.TaskID, e.Message)` 追加 + スピナー開始 |
| `EventSubTaskLog` | ブロック追加なし（内部処理） |
| `EventSubTaskComplete` | 対応する `BlockSubTask` を完了マーク（TaskID で逆順検索） |

---

## イベントライフサイクル

### コマンド実行: CmdStart → CmdOutput → CmdDone

```
Loop.runCommand()
    │
    ├── emit(EventCmdStart{Message: "nmap -sV 10.0.0.5"})
    │       → TUI: NewCommandBlock("nmap -sV 10.0.0.5") 追加
    │
    ├── streamAndCollect() — 出力をストリーミング
    │   ├── emit(EventCmdOutput{OutputLine: "Starting Nmap..."})
    │   │       → TUI: 最後の BlockCommand.Output に追記
    │   ├── emit(EventCmdOutput{OutputLine: "22/tcp open ssh"})
    │   │       → TUI: 最後の BlockCommand.Output に追記
    │   └── ... (繰り返し)
    │
    └── emit(EventCmdDone{ExitCode: 0, Duration: 12s, Message: "exit 0 (45 lines)"})
            → TUI: 最後の BlockCommand を完了マーク
```

### 思考: ThinkStart → ThinkDone

```
Loop.Run() — Brain.Think() 呼び出し前後
    │
    ├── emit(EventThinkStart{})
    │       → TUI: NewThinkingBlock() 追加、スピナー開始
    │
    ├── Brain.Think(ctx, input)  ← ここで LLM API 呼び出し
    │
    └── emit(EventThinkDone{Duration: 3s})
            → TUI: 最後の BlockThinking を完了マーク
            → "✻ Completed in 3s" と表示
```

### サブタスク: SubTaskStart → SubTaskComplete

```
Loop.handleSpawnTask()
    │
    └── emit(EventSubTaskStart{TaskID: "task-1", Message: "Scan all TCP ports"})
            → TUI: NewSubTaskBlock("task-1", "Scan all TCP ports") 追加、スピナー開始

... (サブタスクが別 goroutine で実行中) ...

    emit(EventSubTaskLog{TaskID: "task-1", Message: "..."})
            → TUI: 何もしない（内部処理）

    emit(EventSubTaskComplete{TaskID: "task-1"})
            → TUI: TaskID が一致する BlockSubTask を逆順検索し完了マーク
            → "̶S̶c̶a̶n̶ ̶a̶l̶l̶ ̶T̶C̶P̶ ̶p̶o̶r̶t̶s̶ ✓ 45s" と表示
```

### ストール: Stalled → UserMsg → 復帰

```
Loop.Run() — ストール検知
    │
    ├── emit(EventStalled{Message: "Stalled after 3 consecutive failures..."})
    │       → TUI: 警告メッセージ + 操作ガイド表示
    │
    ├── waitForUserMsg(ctx)  ← ブロッキング待機
    │       ← TUI: ユーザーが入力送信
    │
    └── consecutiveFailures = 0, Status = SCANNING
        → ループ継続
```

---

## スピナー管理

### 開始条件

`EventThinkStart` または `EventSubTaskStart` 受信時、`m.spinning` が `false` の場合にスピナーを開始:

```go
if !m.spinning {
    m.spinning = true
    spinnerCmd = m.spinner.Tick
}
```

### 停止条件

`EventThinkDone`, `EventCmdDone`, `EventSubTaskComplete` 受信後に `hasActiveSpinner()` を呼び出し、未完了のスピナーブロックが残っていなければ `m.spinning = false`:

```go
m.spinning = m.hasActiveSpinner()
```

`hasActiveSpinner()` は以下をチェック:
- `BlockThinking` で `ThinkingDone == false`
- `BlockSubTask` で `TaskDone == false`

---

## 関連ファイル

| ファイル | 役割 |
|---------|------|
| `internal/agent/event.go` | EventType 定数、Event 構造体定義 |
| `internal/agent/loop.go` | `emit()` — イベント送信、各アクションからのイベント発行 |
| `internal/agent/target.go` | LogSource 定義、Target.AddBlock() |
| `internal/tui/update.go` | `handleAgentEvent()` — イベント受信・ブロック変換 |
| `internal/tui/model.go` | `rebuildViewport()` — ブロック→ビューポート描画 |
| `cmd/pentecter/main.go` | `events` チャネル生成（バッファ 512） |
