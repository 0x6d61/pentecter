# タスク完了プッシュモデル — SubAgent アーキテクチャ v2

## 概要

SubAgent の結果取得を **Pull（ポーリング）→ Push（完了通知）** に変更する。
同時に TaskKindRunner を廃止し、spawn_task は SmartSubAgent 専用にする。

## 背景と問題

現状の SubAgent アーキテクチャでは、Brain が `check_task` を繰り返し呼び出して
タスクの完了を確認する **Pull ベース** モデルを採用している。

```
Brain: spawn_task("nmap full scan")
Brain: Think() → check_task     ← LLM 呼び出し（トークン消費）
Brain: Think() → check_task     ← LLM 呼び出し（トークン消費）
Brain: Think() → check_task     ← LLM 呼び出し（トークン消費）
Brain: Think() → "done!"        ← やっと有用な応答
```

### 問題点

1. **LLM トークンの浪費**: タスク実行中も毎回 Brain.Think() を呼ぶ
2. **クラッシュリスク**: 連続ポーリングでスタール検出が誤発動、
   または `Complete()` の二重呼び出しで panic (`close of closed channel`)
3. **10秒クールダウンの限界**: PR #44 で導入したが、根本解決にならない
4. **Runner の存在意義**: `spawn_task(smart=false)` は非同期化した `run` に過ぎず、
   単一ターゲット内で Runner の非同期が活きる場面がない

## 設計方針

### Runner 廃止

| 変更前 | 変更後 |
|--------|--------|
| `run` — 同期コマンド実行 | `run` — 同期コマンド実行（変更なし） |
| `spawn_task(smart=false)` — Runner | **廃止** |
| `spawn_task(smart=true)` — SmartSubAgent | `spawn_task` — SmartSubAgent のみ |
| `check_task` — ポーリング | **廃止** |
| `wait` — 完了待ち | `wait` — 維持（複数タスク待ちに使用） |
| `kill_task` — タスク中止 | `kill_task` — 維持 |

**理由**:
- 単純コマンドは `run` で十分（Brain は結果を待って次の判断をする）
- 複数ターゲットの並列は Team/Loop が担当する
- 並行調査が必要な場面では SmartSubAgent が適切

### 完了プッシュモデル

SmartSubAgent の結果取得を Push ベースに変更する。

```
変更前 (Pull):
  Brain.Think() → spawn_task
  Brain.Think() → check_task → "(no new output)"   ← 無駄
  Brain.Think() → check_task → "(no new output)"   ← 無駄
  Brain.Think() → check_task → "done: 結果..."

変更後 (Push):
  Brain.Think() → spawn_task
  Brain.Think() → (他の作業 or wait)
  ... SubAgent が自律実行中 ...
  SubAgent 完了 → 結果を自動注入 → Brain.Think() に渡る
```

## 詳細設計

### 1. TaskManager の変更

```go
// DrainCompleted は完了済みタスクの結果を取り出す。
// 一度取り出した結果は二度と返さない。
func (tm *TaskManager) DrainCompleted() []*SubTask {
    tm.mu.Lock()
    defer tm.mu.Unlock()

    var completed []*SubTask
    for {
        select {
        case id := <-tm.doneCh:
            if task, ok := tm.tasks[id]; ok {
                completed = append(completed, task)
            }
        default:
            return completed
        }
    }
}
```

### 2. Loop の変更

Brain.Think() の直前で完了タスクを drain し、結果を注入する。

```go
// ループ本体（簡略）
for {
    // 1. ユーザーメッセージを drain
    userMsg = l.drainUserMsg()

    // 2. 完了タスクの結果を注入（新規）
    if completedOutput := l.drainCompletedTasks(); completedOutput != "" {
        l.lastToolOutput = appendIfNotEmpty(l.lastToolOutput, completedOutput)
    }

    // 3. Brain.Think()
    action, err = l.br.Think(ctx, ...)

    // 4. アクション実行
    switch action.Action {
    case "run":          l.handleRun(ctx, action)
    case "spawn_task":   l.handleSpawnTask(ctx, action)  // SmartSubAgent のみ
    case "wait":         l.handleWait(ctx, action)
    case "kill_task":    l.handleKillTask(ctx, action)
    // check_task は削除
    }
}
```

```go
// drainCompletedTasks は完了した SubAgent の結果をフォーマットする。
func (l *Loop) drainCompletedTasks() string {
    if l.taskMgr == nil {
        return ""
    }

    completed := l.taskMgr.DrainCompleted()
    if len(completed) == 0 {
        return ""
    }

    var sb strings.Builder
    for _, task := range completed {
        sb.WriteString(fmt.Sprintf("=== SubTask Completed: %s ===\n", task.ID))
        sb.WriteString(task.Summary())
        sb.WriteString("\n")
        if len(task.Findings) > 0 {
            sb.WriteString("Findings:\n")
            for _, f := range task.Findings {
                sb.WriteString(fmt.Sprintf("  - %s\n", f))
            }
        }
        output := task.FullOutput()
        if output != "" {
            sb.WriteString("Output:\n")
            sb.WriteString(output)
            sb.WriteString("\n")
        }
        // Entity をターゲットに追加
        if len(task.Entities) > 0 {
            l.target.AddEntities(task.Entities)
        }
    }
    return sb.String()
}
```

### 3. spawn_task アクションの変更

`TaskKind` フィールドを廃止。spawn_task は常に SmartSubAgent を起動する。

```go
// handleSpawnTask — SmartSubAgent のみ
func (l *Loop) handleSpawnTask(ctx context.Context, action *schema.Action) {
    req := SpawnTaskRequest{
        Kind:    TaskKindSmart,  // 常に Smart
        Goal:    action.TaskGoal,
        // Command フィールドは不要（SubAgent が自分で判断）
        // ...
    }
    // ...
}
```

### 4. Action スキーマの変更

```go
// 廃止
// ActionCheckTask ActionType = "check_task"

// spawn_task から削除するフィールド
// TaskKind は不要（常に smart）
// Command は不要（SubAgent が自律判断）
```

### 5. Brain プロンプトの変更

```
変更前:
- spawn_task: Start a background task. Set smart=true for autonomous sub-agent.
- check_task: Read partial output from a running task (non-blocking).

変更後:
- spawn_task: Start an autonomous sub-agent for parallel investigation.
  The sub-agent runs independently and results are automatically
  delivered when it completes. No need to check status.
```

`check_task` の説明とポーリングのガイドラインを削除し、
完了プッシュの説明に置き換える。

## 削除対象コード

| ファイル | 削除内容 |
|----------|----------|
| `internal/agent/task_runner.go` | **ファイルごと削除** |
| `internal/agent/loop_tasks.go` | `handleCheckTask()` 関数を削除 |
| `internal/agent/loop.go` | `case ActionCheckTask:` 分岐を削除 |
| `internal/agent/subtask.go` | `TaskKindRunner` 定数を削除 |
| `internal/agent/task_manager.go` | Runner 分岐を削除、`DrainCompleted()` を追加 |
| `pkg/schema/action.go` | `ActionCheckTask` 定数を削除、`TaskKind` フィールドを削除 |
| `internal/brain/prompt.go` | check_task の説明を削除、完了プッシュの説明を追加 |

## テスト方針

### ユニットテスト

1. **DrainCompleted のテスト**: タスク完了 → DrainCompleted() で取得 → 2回目は空
2. **drainCompletedTasks のテスト**: 完了タスクの結果が正しくフォーマットされること
3. **spawn_task のテスト**: SmartSubAgent が起動し、完了時に doneCh に通知されること
4. **Loop 統合テスト**: spawn_task → SubAgent 完了 → 次の Brain.Think() に結果が注入されること

### 既存テスト

- `TestLoop_Run_CheckTask` → 削除（check_task 廃止のため）
- `TestCheckTaskCooldown_Unit` → 削除
- `TestLoop_Run_SpawnTask` → SmartSubAgent のみに修正

## 影響範囲

- **Brain プロンプト**: check_task の説明削除、完了プッシュの説明追加
- **TUI**: EventSubTask 系イベントは変更なし（SmartSubAgent が引き続き発火）
- **設計ドキュメント**: `subagent-architecture.md` を本ドキュメントで補完
