# SubAgent アーキテクチャ設計

## 概要

pentecter の Brain（メインエージェント）が、独立したサブタスクを並列に生成・管理する仕組みの設計。
現在の逐次実行モデル（1コマンドずつ実行 → 結果待ち → 次コマンド）を拡張し、
複数の偵察・攻撃タスクを同時に進行させることで、ペネトレーションテストの効率を大幅に向上させる。

---

## 背景と課題

### 現状のモデル（逐次ブロッキング）

```
Brain → run(nmap -sV 10.0.0.5) → 待機 → 結果 → Brain → run(nikto ...) → 待機 → 結果 → ...
```

**問題点:**
- nmap のフルスキャン（数分〜数十分）中、Brain は何もできない
- 独立した偵察タスク（ポートスキャン、DNS偵察、Web脆弱性スキャン）を同時実行できない
- ターゲット内の複数サービスに対する攻撃が直列になり、全体の所要時間が長い
- Brain のコンテキストが単一タスクの詳細で圧迫される

### 目標のモデル（並列実行）

```
Brain → spawn_task("port_scan", "nmap -sV -p- 10.0.0.5")
      → spawn_task("web_recon", "nikto -h http://10.0.0.5/")
      → spawn_task("dns_recon", "dig @10.0.0.5 AXFR example.com")
      → ... 他の思考を継続 ...
      → check_task("port_scan") → 完了済み → 結果を取得
      → check_task("web_recon") → まだ実行中
      → wait(["port_scan", "web_recon"]) → 両方完了を待機
```

---

## アーキテクチャ概要

```
┌─────────────────────────────────────────────────────────┐
│  Agent Loop (メインスレッド)                              │
│                                                         │
│  Brain.Think() → Action{spawn_task} ─┐                  │
│                                      │                  │
│  ┌───────────────────────────────────▼────────────────┐ │
│  │           TaskManager                              │ │
│  │                                                    │ │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐           │ │
│  │  │TaskRunner│ │TaskRunner│ │TaskRunner│  ...       │ │
│  │  │ goroutine│ │ goroutine│ │ goroutine│           │ │
│  │  └────┬─────┘ └────┬─────┘ └────┬─────┘           │ │
│  │       │             │             │                │ │
│  │       ▼             ▼             ▼                │ │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐           │ │
│  │  │SubTask  │  │SubTask  │  │SubTask  │           │ │
│  │  │ result  │  │ result  │  │ result  │           │ │
│  │  │ channel │  │ channel │  │ channel │           │ │
│  │  └─────────┘  └─────────┘  └─────────┘           │ │
│  │                                                    │ │
│  │  TaskTree (親子関係の追跡)                           │ │
│  └────────────────────────────────────────────────────┘ │
│                                                         │
│  Brain.Think() ← check_task / wait → 結果取得           │
│                                                         │
└─────────────────────────────────────────────────────────┘
         │                    │
         ▼                    ▼
   ┌──────────┐        ┌──────────┐
   │ TUI      │        │ ToolExec │
   │ (イベント │        │ (コマンド │
   │  表示)    │        │  実行)    │
   └──────────┘        └──────────┘
```

---

## 新しい Action タイプ

### spawn_task — サブタスクの生成

Brain がサブタスクを生成する。タスクは独立した goroutine で非同期実行される。

```json
{
  "thought": "nmap フルスキャンは時間がかかるので、並行して nikto も実行する",
  "action": "spawn_task",
  "task_id": "port_scan",
  "task_description": "Full port scan on target",
  "command": "nmap -sV -p- 10.0.0.5"
}
```

| フィールド | 型 | 説明 |
|-----------|---|------|
| task_id | string | タスクの一意識別子（Brain が命名） |
| task_description | string | タスクの目的（ログ・デバッグ用） |
| command | string | 実行するコマンド |

**制約:**
- 同一 `task_id` のタスクが実行中の場合はエラーを返す
- 承認ゲートは通常の `run` アクションと同じルールに従う（Docker / ホスト実行の判定）
- 同時実行タスク数に上限を設ける（デフォルト: 8）

### wait — タスク完了の待機

指定したタスクの完了を待機する。タイムアウトを指定可能。

```json
{
  "thought": "ポートスキャンと Web 偵察の結果を待つ",
  "action": "wait",
  "task_ids": ["port_scan", "web_recon"],
  "timeout_seconds": 300
}
```

| フィールド | 型 | 説明 |
|-----------|---|------|
| task_ids | []string | 待機対象のタスク ID リスト |
| timeout_seconds | int | タイムアウト秒数（省略時: 600） |

**動作:**
- 指定したすべてのタスクが完了するまでブロック
- タイムアウトした場合、完了済みのタスク結果 + 未完了タスクのステータスを返す
- 待機中も TUI にはリアルタイムでタスク進捗が表示される

### check_task — タスク状態の確認

タスクの状態をノンブロッキングで確認する。完了していれば結果も取得する。

```json
{
  "thought": "ポートスキャンが終わったか確認する",
  "action": "check_task",
  "task_id": "port_scan"
}
```

| フィールド | 型 | 説明 |
|-----------|---|------|
| task_id | string | 確認対象のタスク ID |

**レスポンス形式（Brain への入力として返す）:**

実行中の場合:
```
Task "port_scan" is still running (elapsed: 45s)
```

完了の場合:
```
Task "port_scan" completed (exit code: 0, 128 lines)
--- Output ---
{truncated output}
```

失敗の場合:
```
Task "port_scan" failed (exit code: 1)
Error: Connection refused
```

### kill_task — タスクの強制終了

実行中のタスクをキャンセルする。

```json
{
  "thought": "nmap が長すぎるのでキャンセルして別のアプローチを試す",
  "action": "kill_task",
  "task_id": "port_scan"
}
```

| フィールド | 型 | 説明 |
|-----------|---|------|
| task_id | string | 終了対象のタスク ID |

**動作:**
- タスクの context をキャンセルし、プロセスに SIGTERM を送信
- 5秒以内に終了しない場合は SIGKILL
- キャンセル時点までの出力は保持される

---

## コンポーネント詳細

### SubTask

サブタスクの状態を表現する構造体。

```go
type SubTaskStatus string

const (
    SubTaskPending  SubTaskStatus = "pending"
    SubTaskRunning  SubTaskStatus = "running"
    SubTaskDone     SubTaskStatus = "done"
    SubTaskFailed   SubTaskStatus = "failed"
    SubTaskKilled   SubTaskStatus = "killed"
)

type SubTask struct {
    ID          string
    Description string
    Command     string
    Status      SubTaskStatus
    ExitCode    int
    Output      string         // 切り捨て済み出力
    RawOutput   string         // 全出力（Log Store 用）
    StartedAt   time.Time
    FinishedAt  time.Time
    ParentID    string         // 親タスク ID（ネスト時）
    Error       error          // 実行エラー
}
```

### TaskRunner

1 つのサブタスクを goroutine 内で実行するワーカー。

```go
type TaskRunner struct {
    task     *SubTask
    ctx      context.Context
    cancel   context.CancelFunc
    done     chan struct{}
    executor ToolExecutor     // コマンド実行インターフェース
}

func NewTaskRunner(task *SubTask, executor ToolExecutor) *TaskRunner
func (r *TaskRunner) Run(ctx context.Context)   // goroutine で実行
func (r *TaskRunner) Wait() <-chan struct{}      // 完了チャネル
func (r *TaskRunner) Kill()                      // 強制終了
```

**実行フロー:**

1. `task.Status` を `SubTaskRunning` に変更
2. `executor.Execute()` でコマンドを実行
3. 完了時に `task.Status` を `SubTaskDone` / `SubTaskFailed` に変更
4. `done` チャネルをクローズして完了を通知
5. context がキャンセルされた場合は `SubTaskKilled` に変更

### SmartSubAgent

SubAgent に独自の Brain（LLM）を持たせ、単一コマンド実行ではなく
複数ステップの自律タスクを実行できるようにする拡張コンポーネント。

```go
type SmartSubAgent struct {
    TaskRunner                    // 埋め込み
    brain      brain.Brain        // サブエージェント用 Brain
    maxTurns   int                // 最大ターン数（デフォルト: 10）
    model      string             // 使用モデル（SUBAGENT_MODEL）
    provider   string             // 使用プロバイダ（SUBAGENT_PROVIDER）
}

func NewSmartSubAgent(task *SubTask, brainCfg brain.Config) *SmartSubAgent
func (s *SmartSubAgent) Run(ctx context.Context)
```

**SmartSubAgent のループ:**

```
SmartSubAgent.Run():
  for turn := 0; turn < maxTurns; turn++ {
      action := brain.Think(taskContext)
      switch action.Action {
      case "run":
          result := executor.Execute(action.Command)
          taskContext.Update(result)
      case "complete":
          task.Output = action.Summary
          return
      case "fail":
          task.Error = errors.New(action.Reason)
          return
      }
  }
  // maxTurns 到達 → 自動完了
```

**使用例:**

```json
{
  "thought": "Web アプリの認証バイパスを網羅的に調査するサブエージェントを起動",
  "action": "spawn_task",
  "task_id": "auth_bypass",
  "task_description": "Web authentication bypass testing",
  "smart": true,
  "task_prompt": "Perform authentication bypass testing on http://10.0.0.5/login."
}
```

`smart: true` が指定された場合、TaskManager は TaskRunner の代わりに SmartSubAgent を生成する。

### TaskManager

全サブタスクのライフサイクルを管理するオーケストレータ。

```go
type TaskManager struct {
    mu       sync.RWMutex
    tasks    map[string]*TaskRunner       // task_id → runner
    tree     *TaskTree                    // 親子関係
    maxTasks int                          // 同時実行上限
    events   chan<- agent.Event           // TUI へのイベント送信
    executor ToolExecutor                 // コマンド実行
}

func NewTaskManager(maxTasks int, events chan<- agent.Event, executor ToolExecutor) *TaskManager
func (m *TaskManager) Spawn(task *SubTask) error
func (m *TaskManager) Check(taskID string) *SubTask
func (m *TaskManager) Wait(ctx context.Context, taskIDs []string, timeout time.Duration) map[string]*SubTask
func (m *TaskManager) Kill(taskID string) error
func (m *TaskManager) ListActive() []*SubTask
func (m *TaskManager) Cleanup()                     // 完了済みタスクの掃除
```

### TaskTree

サブタスクの親子関係を追跡する。SmartSubAgent が子タスクをスポーンした場合に使用。

```go
type TaskTree struct {
    mu       sync.RWMutex
    children map[string][]string    // parent_id → []child_id
    parent   map[string]string      // child_id → parent_id
}

func (t *TaskTree) AddChild(parentID, childID string)
func (t *TaskTree) GetChildren(parentID string) []string
func (t *TaskTree) GetParent(childID string) string
func (t *TaskTree) RemoveTask(taskID string)
```

**ツリー構造の例:**

```
root (メインエージェント)
  ├── port_scan (TaskRunner — 単純コマンド実行)
  ├── web_recon (SmartSubAgent — 自律ループ)
  │     ├── web_recon/nikto (子タスク)
  │     └── web_recon/dirb (子タスク)
  └── dns_recon (TaskRunner — 単純コマンド実行)
```

---

## 並行処理モデル

### goroutine 設計

各 TaskRunner / SmartSubAgent は独立した goroutine で動作する。
メインの Agent Loop スレッドとは channel で通信する。

```
Agent Loop goroutine
  │
  ├── TaskRunner goroutine (port_scan)
  │     └── os/exec プロセス
  │
  ├── SmartSubAgent goroutine (web_recon)
  │     ├── Brain.Think() (HTTP 呼び出し)
  │     └── os/exec プロセス
  │
  └── TaskRunner goroutine (dns_recon)
        └── os/exec プロセス
```

### channel ベースの完了通知

```go
// TaskRunner.Run() 内
func (r *TaskRunner) Run(ctx context.Context) {
    defer close(r.done)

    r.task.Status = SubTaskRunning
    r.task.StartedAt = time.Now()
    r.emitEvent(EventSubTaskStarted)

    result, err := r.executor.Execute(ctx, r.task.Command)

    r.task.FinishedAt = time.Now()
    if err != nil {
        r.task.Status = SubTaskFailed
        r.task.Error = err
    } else {
        r.task.Status = SubTaskDone
        r.task.ExitCode = result.ExitCode
        r.task.Output = truncateOutput(result.Output)
        r.task.RawOutput = result.Output
    }
    r.emitEvent(EventSubTaskCompleted)
}
```

### Pull ベースの出力取得

サブタスクの出力はメインの Agent Loop が明示的にリクエスト（`check_task` / `wait`）したときのみ Brain に渡す。
Push 方式（完了時に即座に Brain のコンテキストに注入）ではない。

**理由:**
- Brain のコンテキストウィンドウを節約する
- Brain が「いつ結果を確認するか」を自律的に判断できる
- 複数タスクが同時に完了しても、Brain は1つずつ順序立てて処理できる

**例外:** `wait` アクションでは、指定した全タスクの結果をまとめて返す。

---

## イベントフロー（SubTask ライフサイクル）

### 新規イベントタイプ

```go
const (
    EventSubTaskSpawned   EventType = "subtask_spawned"
    EventSubTaskStarted   EventType = "subtask_started"
    EventSubTaskOutput    EventType = "subtask_output"
    EventSubTaskCompleted EventType = "subtask_completed"
    EventSubTaskKilled    EventType = "subtask_killed"
    EventSubTaskError     EventType = "subtask_error"
)
```

### イベントシーケンス

```
Brain: spawn_task("port_scan", "nmap -sV -p- 10.0.0.5")
  │
  ├── EventSubTaskSpawned   → TUI: "Spawned task: port_scan (nmap -sV -p- 10.0.0.5)"
  ├── EventSubTaskStarted   → TUI: "Task port_scan started"
  │
  │   (... 数分後 ...)
  │
  ├── EventSubTaskOutput    → TUI: ストリーミング出力（オプション）
  ├── EventSubTaskCompleted → TUI: "Task port_scan completed (exit 0, 128 lines)"
  │
  └── Brain: check_task("port_scan")
        └── 結果を Brain の次ターン入力に含める
```

### TUI 表示

TUI のログパネルにサブタスク関連のイベントが表示される。
タスク ID がプレフィックスとして付与され、どのタスクのログかが識別可能。

```
[14:23:01] [SUBTASK] Spawned: port_scan — nmap -sV -p- 10.0.0.5
[14:23:01] [SUBTASK] Spawned: web_recon — nikto -h http://10.0.0.5/
[14:23:02] [SUBTASK] Started: port_scan
[14:23:02] [SUBTASK] Started: web_recon
[14:25:30] [SUBTASK] Completed: web_recon (exit 0, 42 lines)
[14:28:15] [SUBTASK] Completed: port_scan (exit 0, 128 lines)
```

---

## Brain プロンプトへの追加

### システムプロンプトへの追加セクション

```
PARALLEL EXECUTION:
You can run multiple commands in parallel using sub-tasks.

Available actions for parallel execution:
- "spawn_task": Start a command as a background task
  Required fields: task_id, task_description, command
  Optional fields: smart (bool), task_prompt (string, for smart sub-agents)
- "check_task": Check if a background task has completed (non-blocking)
  Required fields: task_id
- "wait": Block until specified tasks complete
  Required fields: task_ids (array)
  Optional fields: timeout_seconds (default: 600)
- "kill_task": Cancel a running background task
  Required fields: task_id

Guidelines:
- Use spawn_task when a command will take a long time (nmap full scan, brute force, etc.)
- Use spawn_task for independent reconnaissance tasks that can run simultaneously
- Use check_task to poll task status without blocking
- Use wait when you need results from multiple tasks before proceeding
- Each task_id must be unique and descriptive (e.g., "full_port_scan", "web_nikto", "dns_axfr")
- Maximum concurrent tasks: {maxTasks}
- Smart sub-agents (smart: true) run their own autonomous loop with a separate LLM
  Use them for complex multi-step investigations

ACTIVE TASKS:
{dynamically generated list of running/completed tasks}
```

### ユーザープロンプトへのタスクステータス追加

Brain の各ターンのプロンプトに、アクティブなサブタスクの状態を含める:

```
## Active Sub-Tasks
| Task ID     | Status   | Elapsed | Command                        |
|-------------|----------|---------|--------------------------------|
| port_scan   | running  | 2m 15s  | nmap -sV -p- 10.0.0.5         |
| web_recon   | done     | 1m 42s  | nikto -h http://10.0.0.5/      |
| dns_recon   | failed   | 0m 03s  | dig @10.0.0.5 AXFR example.com |
```

---

## 設定: 環境変数

### SUBAGENT_MODEL

SmartSubAgent が使用する LLM モデルを指定する。
メインの Brain と異なるモデル（軽量・高速なモデル）を使い分けることができる。

```bash
# 例: メインは Claude Opus、サブエージェントは Claude Sonnet
ANTHROPIC_MODEL=claude-opus-4-0-20250514
SUBAGENT_MODEL=claude-sonnet-4-20250514
```

| 値 | 説明 |
|---|------|
| 未設定 | メインの Brain と同じモデルを使用 |
| モデル名 | 指定したモデルを SmartSubAgent に使用 |

### SUBAGENT_PROVIDER

SmartSubAgent が使用する LLM プロバイダを指定する。
メインと異なるプロバイダを使うことで、レート制限の分散やコスト最適化が可能。

```bash
# 例: メインは Anthropic 直接、サブエージェントは OpenRouter 経由
ANTHROPIC_API_KEY=sk-ant-...
SUBAGENT_PROVIDER=openrouter
OPENROUTER_API_KEY=sk-or-...
```

| 値 | 説明 |
|---|------|
| 未設定 | メインの Brain と同じプロバイダを使用 |
| anthropic | Anthropic API 直接 |
| openai | OpenAI 互換 API |
| openrouter | OpenRouter 経由 |
| ollama | Ollama ローカル推論 |

### SUBAGENT_MAX_TASKS

同時実行可能なサブタスク数の上限。

```bash
SUBAGENT_MAX_TASKS=8   # デフォルト: 8
```

### SUBAGENT_MAX_TURNS

SmartSubAgent の最大ターン数。

```bash
SUBAGENT_MAX_TURNS=10   # デフォルト: 10
```

---

## schema.Action の拡張

```go
const (
    ActionSpawnTask ActionType = "spawn_task"
    ActionCheckTask ActionType = "check_task"
    ActionWait      ActionType = "wait"
    ActionKillTask  ActionType = "kill_task"
)

type Action struct {
    // 既存フィールド
    Thought   string         `json:"thought"`
    Action    ActionType     `json:"action"`
    Command   string         `json:"command,omitempty"`
    Memory    *Memory        `json:"memory,omitempty"`
    Target    string         `json:"target,omitempty"`
    MCPServer string         `json:"mcp_server,omitempty"`
    MCPTool   string         `json:"mcp_tool,omitempty"`
    MCPArgs   map[string]any `json:"mcp_args,omitempty"`

    // SubAgent 関連フィールド
    TaskID          string   `json:"task_id,omitempty"`
    TaskDescription string   `json:"task_description,omitempty"`
    TaskIDs         []string `json:"task_ids,omitempty"`
    TimeoutSeconds  int      `json:"timeout_seconds,omitempty"`
    Smart           bool     `json:"smart,omitempty"`
    TaskPrompt      string   `json:"task_prompt,omitempty"`
}
```

---

## Agent Loop のディスパッチ拡張

```go
case schema.ActionSpawnTask:
    l.spawnTask(ctx, action)

case schema.ActionCheckTask:
    result := l.taskManager.Check(action.TaskID)
    l.feedTaskResultToBrain(result)

case schema.ActionWait:
    timeout := time.Duration(action.TimeoutSeconds) * time.Second
    if timeout == 0 {
        timeout = 600 * time.Second
    }
    results := l.taskManager.Wait(ctx, action.TaskIDs, timeout)
    l.feedTaskResultsToBrain(results)

case schema.ActionKillTask:
    l.taskManager.Kill(action.TaskID)
```

### spawnTask の処理フロー

```go
func (l *Loop) spawnTask(ctx context.Context, action schema.Action) {
    task := &SubTask{
        ID:          action.TaskID,
        Description: action.TaskDescription,
        Command:     action.Command,
        Status:      SubTaskPending,
        ParentID:    "root",
    }

    // 承認ゲートチェック（通常の run と同じロジック）
    if needsProposal(action.Command) {
        l.emit(EventProposal, action)
        approved := l.waitForApproval()
        if !approved {
            return
        }
    }

    if action.Smart {
        // SmartSubAgent を生成
        brainCfg := l.buildSubAgentBrainConfig()
        err := l.taskManager.SpawnSmart(task, brainCfg, action.TaskPrompt)
    } else {
        // 通常の TaskRunner を生成
        err := l.taskManager.Spawn(task)
    }
}
```

---

## 承認ゲートとの統合

サブタスクの承認は通常のコマンド実行と同じルールに従う:

| 実行方式 | 承認 |
|----------|------|
| Docker 実行ツール | 自動実行 |
| ホスト実行ツール | 要承認（Proposal） |
| `proposal_required: false` 明示 | 自動実行 |
| グローバル Auto-Approve 有効 | 自動実行 |

SmartSubAgent 内で実行されるコマンドも同じルールが適用される。
SmartSubAgent が承認待ちになった場合、TUI にその旨が表示され、ユーザーが承認するまでサブエージェントのループは一時停止する。

---

## 関連ファイル

| ファイル | 関連 |
|---------|------|
| `pkg/schema/action.go` | Action 型定義の拡張 |
| `internal/agent/loop.go` | Agent Loop ディスパッチの拡張 |
| `internal/agent/subtask.go` | SubTask, TaskRunner, SmartSubAgent 実装 |
| `internal/agent/taskmanager.go` | TaskManager 実装 |
| `internal/agent/tasktree.go` | TaskTree 実装 |
| `internal/agent/event.go` | SubTask 関連イベントタイプ追加 |
| `internal/brain/prompt.go` | システムプロンプトの PARALLEL EXECUTION セクション |
| `internal/brain/brain.go` | SmartSubAgent 用 Brain 設定 |
| `docs/architecture_design/execution-model.md` | コマンド実行モデル（参照） |
| `docs/architecture_design/design-philosophy.md` | Agent Team 設計（参照） |
