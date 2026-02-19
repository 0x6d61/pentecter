# 失敗検知・ストール検知設計

## 概要

pentecter の Agent ループは、コマンド実行結果を自動評価して失敗を検知する仕組みを持つ。
連続失敗が閾値に達すると **ストール状態** と判定し、ユーザーに方針の指示を求めて一時停止する。
これにより、同じ失敗を繰り返す無限ループを防止する。

---

## 結果評価フロー

### evaluateResult() の呼び出しタイミング

`evaluateResult()` はツール出力を伴うアクションの実行後にのみ呼び出される:

| アクション | evaluateResult() | 理由 |
|-----------|:---:|------|
| `run` (コマンド実行) | YES | コマンドの成否を判定する必要がある |
| `call_mcp` (MCP ツール呼び出し) | YES | ツール出力の成否を判定する必要がある |
| `think` (思考のみ) | NO | 外部実行を伴わない |
| `check_task` (サブタスク確認) | NO | 状態確認のみ |
| `memory` (記録) | NO | 副作用のない記録操作 |
| `propose` (提案) | NO | ユーザー承認を待つ別フロー |
| `spawn_task` (サブタスク生成) | NO | タスク生成のみ |
| `wait` (待機) | NO | サブタスク完了を待つのみ |
| `search_knowledge` | NO | 読み取り専用 |
| `read_knowledge` | NO | 読み取り専用 |
| `complete` (完了) | NO | ループ終了 |

### コード上の位置

```go
// internal/agent/loop.go — Run() 内の switch 文

case schema.ActionRun:
    l.runCommand(ctx, action.Command)
    l.evaluateResult()         // ← ここ

case schema.ActionCallMCP:
    l.callMCP(ctx, action)
    l.evaluateResult()         // ← ここ

case schema.ActionThink:
    // 思考のみ — evaluateResult() なし
```

---

## 3つの失敗シグナル

`evaluateResult()` は以下の 3 つのシグナルで失敗を判定する。いずれか 1 つでも該当すれば `failed = true`。

### Signal A: Exit Code

```go
failed := l.lastExitCode != 0
```

- コマンドの終了コードが 0 以外の場合は失敗
- MCP ツールの場合: `result.IsError` が true なら `lastExitCode = 1` が設定される

### Signal B: 出力パターンマッチ (`isFailedOutput()`)

ツール出力に失敗を示す文字列パターンが含まれる場合に失敗と判定する。
exit code が 0 でもこのチェックで失敗判定になり得る（例: nmap が "0 hosts up" を返した場合）。

```go
if isFailedOutput(l.lastToolOutput) {
    failed = true
}
```

#### パターン一覧

**ネットワークエラー:**
| パターン | 想定ケース |
|---------|----------|
| `0 hosts up` | nmap でホストが応答しない |
| `Host seems down` | nmap でホストがダウン |
| `host is down` | 同上（小文字バリアント） |
| `No route to host` | ルーティング不可 |
| `Connection refused` | ポートが閉じている |
| `Connection timed out` | タイムアウト |
| `Network is unreachable` | ネットワーク到達不能 |
| `Name or service not known` | DNS 解決失敗 |
| `couldn't connect to host` | 接続失敗 |

**プログラムエラー:**
| パターン | 想定ケース |
|---------|----------|
| `SyntaxError` | スクリプトの構文エラー |
| `command not found` | コマンドが存在しない |
| `No such file or directory` | ファイル/パスが存在しない |
| `Permission denied` | 権限不足 |
| `Traceback (most recent call last)` | Python 例外 |
| `ModuleNotFoundError` | Python モジュール未インストール |
| `ImportError` | Python インポートエラー |
| `panic:` | Go パニック |
| `NameError` | Python 未定義変数 |
| `Segmentation fault` | セグフォ |

**その他:**
| パターン | 想定ケース |
|---------|----------|
| `Error:` (先頭6文字) | pentecter 自身のエラーメッセージ |
| 空文字列 (`""`) | 出力が空の場合も失敗扱い |

パターンマッチは **大文字小文字を区別しない** (`containsCI()` による case-insensitive 部分一致)。

### Signal C: コマンド繰り返し検知 (`isCommandRepetition()`)

```go
if l.isCommandRepetition() {
    failed = true
}
```

直近 5 件のコマンド履歴で **同一バイナリが 3 回以上** 使われた場合に失敗と判定する。

#### ロジック

1. コマンド履歴 (`l.history`) の直近 5 件を取得
2. 各コマンドから `extractBinary()` でバイナリ名を抽出
   - `"nmap -sV 10.0.0.5"` → `"nmap"`
   - `"/usr/bin/nmap -sV"` → `"nmap"`
3. バイナリ名をカウント
4. いずれかのバイナリが 3 回以上 → `true`

```go
func extractBinary(command string) string {
    // 最初のスペースまでがコマンド部分
    // パス区切り（/ または \）でファイル名だけ抽出
}
```

---

## consecutiveFailures カウンターとストール検知

### カウンターの動作

```go
func (l *Loop) evaluateResult() {
    failed := /* 3つのシグナルで判定 */

    if failed {
        l.consecutiveFailures++    // 連続失敗をインクリメント
    } else {
        l.consecutiveFailures = 0  // 成功で即座にリセット
    }
}
```

- 失敗のたびにインクリメント
- **1回でも成功すれば 0 にリセット** される

### ストール検知閾値

```go
const maxConsecutiveFailures = 3
```

### ストール検知と回復フロー

```
                    evaluateResult()
                         │
                    failed == true?
                    ┌────┴────┐
                    │ YES     │ NO
                    ▼         ▼
         consecutiveFailures++ │ consecutiveFailures = 0
                    │
         >= maxConsecutiveFailures (3)?
                    │
                   YES
                    ▼
         EventStalled 送信
         target.Status = StatusPaused
                    │
                    ▼
         waitForUserMsg() — ブロッキング待機
                    │
                    ▼
         ユーザーからメッセージ受信
         consecutiveFailures = 0  ← リセット
         target.Status = StatusScanning
                    │
                    ▼
         メインループ継続（ユーザーメッセージを Brain に渡す）
```

### EventStalled の TUI 表示

```go
case agent.EventStalled:
    t.AddBlock(agent.NewSystemBlock("⚠ " + e.Message))
    t.AddBlock(agent.NewSystemBlock("Type a message to give the agent new direction."))
```

TUI には以下のように表示される:

```
⚠ Stalled after 3 consecutive failures. Waiting for direction.
Type a message to give the agent new direction.
```

### ストールからの回復

ユーザーが入力欄にメッセージを入力して送信すると:

1. `waitForUserMsg()` がメッセージを受信
2. `consecutiveFailures` が 0 にリセット
3. ターゲットステータスが `SCANNING` に復帰
4. ユーザーメッセージが `pendingUserMsg` に設定され、次のターンで Brain に渡される

---

## ストール検知の位置（メインループ内）

```go
// internal/agent/loop.go — Run() のメインループ冒頭

for {
    // 1. コンテキストキャンセルチェック

    // 2. ユーザーメッセージ回収

    // 3. ★ ストールチェック（ここ）
    if l.consecutiveFailures >= maxConsecutiveFailures {
        l.emit(Event{Type: EventStalled, ...})
        l.target.Status = StatusPaused
        userMsg = l.waitForUserMsg(ctx)  // ブロッキング
        l.consecutiveFailures = 0
        l.target.Status = StatusScanning
    }

    // 4. Brain.Think() 呼び出し
    // 5. アクション実行
}
```

ストールチェックは **Brain.Think() の前** に行われる。これにより、失敗が閾値に達した時点で次の思考サイクルに入る前にユーザーの介入を待つ。

---

## コマンド履歴

`evaluateResult()` と `isCommandRepetition()` が参照するコマンド履歴は `streamAndCollect()` 内で記録される:

```go
type commandEntry struct {
    Command  string
    ExitCode int
    Summary  string    // 出力の先頭200文字
    Time     time.Time
}
```

- 最大 **10件** を保持（超過分は古い順に破棄）
- `isCommandRepetition()` は直近 **5件** のみをチェック

---

## 関連ファイル

| ファイル | 役割 |
|---------|------|
| `internal/agent/loop.go` | `evaluateResult()`, `isFailedOutput()`, `isCommandRepetition()`, ストール検知ロジック |
| `internal/agent/event.go` | `EventStalled` 定義 |
| `internal/tui/update.go` | `EventStalled` の TUI 表示処理 |
