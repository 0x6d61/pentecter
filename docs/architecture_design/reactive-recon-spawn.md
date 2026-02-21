# Reactive ReconTree Spawn — 設計ドキュメント (v2)

## 概要

ReconRunner を「リアクティブ + 協調モデル」に移行する。

**核心的な変更:**
1. Main Agent は **Coordinator** — nmap 実行 + HTTPAgent spawn + 状況判断。**ffuf/dirb/nikto 等の web recon は実行しない**
2. HTTPAgent（per HTTP port）が endpoint fuzz → param fuzz → value fuzz → vhost fuzz のサイクルを自律実行
3. HTTPAgent が **ReconTree を直接更新** — Main と HTTPAgent が共有状態として ReconTree を読み書き
4. `initial_scans` 廃止 — LLM が自由に nmap 戦略を選択
5. **ffuf -recursion 廃止** — HTTPAgent が Recon Queue ベースでタスクを順次消化

## 前提

- ReconTree によるポート/エンドポイント/vhost の構造的追跡が稼働中
- Raw output は `memory/<host>/raw/` に保存済み
- SubAgent (SmartSubAgent) が TaskManager 経由で spawn 可能

## アーキテクチャ

```
┌─────────────────────────────────────────────┐
│  Main Agent (Coordinator)                   │
│  ・nmap 実行 → ReconTree 更新               │
│  ・ReconTree を見て HTTPAgent を spawn       │
│  ・非HTTP サービスの攻撃判断                 │
│  ・ユーザーとのやり取り                      │
│  ・ffuf/dirb/nikto は実行しない ← 重要      │
└──────┬──────────────────────────────────────┘
       │ evaluateResult が新 HTTP ポート検出
       │ → SpawnWebReconForPort 自動呼び出し
       ▼
┌──────────────────────────────────────┐
│ HTTPAgent (per HTTP port)            │
│                                      │
│ 1. endpoint fuzz (ffuf, no recursion)│
│    ↓ 発見した endpoint を ReconTree に追加
│ 2. endpoint profiling (curl)         │
│    ↓                                 │
│ 3. parameter fuzz (ffuf)             │
│    ↓ 発見した param を ReconTree に追加
│ 4. value fuzz (curl)                 │
│    ↓ 脆弱性を ReconTree に追加       │
│ 5. vhost fuzz (ffuf)                 │
│    ↓ 新 vhost 発見 → 1 に戻る        │
│                                      │
│ 全タスク complete → 自動終了          │
└──────────────┬───────────────────────┘
               │ 読み書き
               ▼
┌─────────────────────────────────────────────┐
│          ReconTree (共有状態)                │
│  sync.RWMutex で排他制御                    │
│  ・ポート/エンドポイント/vhost/パラメータ    │
│  ・脆弱性 findings                          │
│  ・全エージェントが読み書き                  │
└─────────────────────────────────────────────┘
```

## Main Agent の役割

### やること
- nmap 実行（戦略は LLM が判断: top-ports → full → UDP）
- evaluateResult で nmap 結果パース → ReconTree 更新
- 新 HTTP ポート検出 → HTTPAgent 自動 spawn
- 非HTTP サービスの攻撃（SSH brute force, MySQL enum 等）
- ReconTree の RECON INTEL を見て状況判断
- ユーザーへの報告・質問対応

### やらないこと（禁止）
- **ffuf, dirb, gobuster, nikto 等の web recon ツール実行**
- HTTPAgent が担当する web 脆弱性テスト
- HTTPAgent と重複する作業

### Main で ffuf 禁止の実装

`loop.go` の `handlePropose()` または `runCommand()` で ffuf/dirb/gobuster/nikto を検出したら:
1. ブロックする（実行しない）
2. "Web recon is handled by HTTPAgent. Focus on non-HTTP services." とログ出力
3. LLM に返すメッセージで HTTPAgent に委譲済みであることを通知

```go
// loop.go
var webReconBlockList = []string{"ffuf", "dirb", "gobuster", "nikto"}

func isWebReconCommand(cmd string) bool {
    for _, tool := range webReconBlockList {
        if strings.Contains(cmd, tool) {
            return true
        }
    }
    return false
}
```

## HTTPAgent の動作

### フロー

```
endpoint fuzz (ffuf -u http://target/FUZZ -of json)
  ↓ ReconTree に endpoint 追加
  ↓ 各 endpoint に param_fuzz/profiling タスクが Pending で追加される
endpoint profiling (curl -isk)
  ↓ 技術スタック判定
parameter fuzz (ffuf -u http://target/endpoint?FUZZ=value -of json)
  ↓ ReconTree に parameter 追加
  ↓ 各 parameter に value_fuzz タスクが Pending で追加される
value fuzz (curl with payloads)
  ↓ 脆弱性を ReconTree に追加
vhost fuzz (ffuf -H "Host: FUZZ.target")
  ↓ 新 vhost 発見 → その vhost の endpoint fuzz に戻る
  ↓ 新 vhost なし → 完了
```

### 停止条件

HTTPAgent は Recon Queue 方式でタスクを消化する。以下の全条件を満たしたら自動終了:
- 全 endpoint の endpoint_enum が Complete
- 全 endpoint の param_fuzz が Complete
- 全 parameter の value_fuzz が Complete
- vhost_discov が Complete（新 vhost なし）
- Pending タスクが 0

### ReconTree 直接更新

HTTPAgent は `SmartSubAgent` 内で ReconTree への参照を持ち、各コマンド実行後に
`DetectAndParse()` を呼んで ReconTree を更新する。

```go
// smart_subagent.go — Run() 内
case schema.ActionRun:
    // コマンド実行
    cmd := action.Command
    linesCh, resultCh := sa.runner.ForceRun(ctx, cmd)
    // ... 結果取得 ...

    // ReconTree 更新（mutex で排他制御）
    if sa.reconTree != nil {
        sa.reconTree.DetectAndParse(cmd, output, exitCode)
    }
```

### recursion 廃止の理由

`-recursion-depth 3` を使うと:
1. 1回の ffuf で全パスが取得されるが、**結果が巨大になりSubAgent のコンテキストを圧迫**
2. ReconTree への追加が一括になり、**段階的な param_fuzz/value_fuzz ができない**
3. Main Agent が同じ ffuf を実行してしまう問題の原因にもなっていた

Recon Queue 方式なら:
1. `/api/` 発見 → ReconTree に追加 → param_fuzz Pending
2. `/api/` の param_fuzz 実行 → parameter 発見
3. `/api/` の value_fuzz 実行 → 脆弱性発見
4. 次のディレクトリ `/docs/` の endpoint_enum へ
5. **タスクがなくなったら自然に停止**

## RECON INTEL（プロンプト注入）

RECON QUEUE を RECON INTEL に置き換える。Main Agent のプロンプトに注入。

```
=== RECON INTEL ===
[BACKGROUND] HTTPAgent active on ports: 80, 443 — do NOT run ffuf/dirb yourself

[FINDINGS]
  Port 80:
    /login.php — SQLi on user param (HIGH)
    /api/v1/users — IDOR suspected (MEDIUM)
  Port 443:
    /admin — basic auth, default creds (LOW)

[ATTACK SURFACE]
  22/tcp SSH OpenSSH 7.2 — not tested
  80/tcp Apache 2.4 — HTTPAgent active
  443/tcp nginx 1.18 — HTTPAgent active
  3306/tcp MySQL 5.7 — not tested
```

### 表示ルール

- `[BACKGROUND]`: HTTPAgent が動作中のポート一覧。Main に ffuf を使わせないための抑制
- `[FINDINGS]`: HTTPAgent が ReconTree に書き込んだ脆弱性。Main の攻撃判断材料
- `[ATTACK SURFACE]`: 全ポート一覧 + ステータス。Main が非HTTP攻撃を計画するための情報
- HTTPAgent 完了後: `[BACKGROUND]` 行が消え、全 findings が `[FINDINGS]` に表示

## evaluateResult のフック設計

```go
func (l *Loop) evaluateResult(cmd string, stdout string, exitCode int) {
    // 既存: DetectAndParse でツール出力をパース → ReconTree 更新
    l.reconTree.DetectAndParse(cmd, stdout, exitCode)

    // 新規: HTTP ポートの新規検出チェック → HTTPAgent 自動 spawn
    for _, port := range l.reconTree.Ports {
        if port.isHTTP() && port.getReconStatus(TaskEndpointEnum) == StatusPending {
            l.reconRunner.SpawnWebReconForPort(l.ctx, port)
        }
    }
}
```

### 二重 spawn 防止

- `SpawnWebReconForPort` は最初に `EndpointEnum` を `StatusInProgress` に変更
- `evaluateResult` は `StatusPending` のポートのみ対象
- `max_parallel` 制限を超える場合は spawn しない（次の evaluateResult で再試行）

## ReconTree の mutex 化

HTTPAgent と Main Agent が同時に ReconTree を読み書きするため、`sync.RWMutex` を追加:

```go
type ReconTree struct {
    mu          sync.RWMutex
    Host        string
    Ports       []*ReconNode
    MaxParallel int
    active      int
    locked      bool
}

// 書き込み操作: Lock()
func (rt *ReconTree) AddPort(port int, service, version string) { ... }
func (rt *ReconTree) AddEndpoint(host string, port int, parent, path string) { ... }

// 読み取り操作: RLock()
func (rt *ReconTree) RenderQueue() string { ... }
func (rt *ReconTree) IsLocked() bool { ... }
```

## SmartSubAgent への ReconTree 注入

```go
// task_manager.go — SpawnTask 内
sa := NewSmartSubAgent(sa.runner, sa.subBrain)
sa.SetReconTree(reconTree)  // ReconTree 参照を渡す

// smart_subagent.go
type SmartSubAgent struct {
    // ... existing fields ...
    reconTree *ReconTree  // nil = ReconTree 更新なし
}

func (sa *SmartSubAgent) SetReconTree(tree *ReconTree) {
    sa.reconTree = tree
}
```

## 変更対象

| ファイル | 変更内容 |
|---|---|
| `internal/agent/recon_tree.go` | `sync.RWMutex` 追加。全メソッドにロック追加 |
| `internal/agent/recon_runner.go` | `RunInitialScans` 削除。recursion 関連削除 |
| `internal/agent/smart_subagent.go` | `reconTree` フィールド追加。実行後に `DetectAndParse` 呼び出し |
| `internal/agent/task_manager.go` | `SpawnTask` で `SetReconTree` 呼び出し |
| `internal/agent/loop.go` | `evaluateResult` に自動 spawn。ffuf ブロック。RECON INTEL 生成 |
| `internal/agent/loop.go` | `initial_scans` 関連削除。`EnsureFfufRecursion` 呼び出し削除 |
| `internal/agent/recon_parser.go` | `EnsureFfufRecursion` 削除。子 endpoint Complete マーク削除 |
| `internal/config/config.go` | `InitialScans` フィールド削除 |
| `internal/agent/team.go` | `InitialScans` フィールド削除 |
| `cmd/pentecter/main.go` | `InitialScans` 設定行削除 |

## 実装順序

1. ReconTree に `sync.RWMutex` 追加
2. SmartSubAgent に `reconTree` フィールド追加 + `DetectAndParse` 呼び出し
3. TaskManager で `SetReconTree` 渡し
4. `EnsureFfufRecursion` 削除 + 子 endpoint Complete マーク削除
5. `initial_scans` 削除（config, loop, team, runner, main）
6. `evaluateResult` に自動 spawn フック
7. Main の ffuf ブロック機構
8. RECON INTEL 生成（RenderQueue 置き換え）
9. HTTPAgent プロンプト更新（recursion 削除、タスクベース）
10. 全テスト + lint 確認

## 設計根拠

### なぜ Main で ffuf を禁止するか

- HTTPAgent が web recon を完全に担当 → Main が ffuf を実行すると重複
- Main の ffuf 実行は TUI フリーズの原因（大量出力がコンテキストを圧迫）
- Main は nmap + 非HTTP攻撃 + 状況判断に専念すべき

### なぜ recursion を廃止するか

- recursion depth 3 の結果が巨大 → SubAgent コンテキスト圧迫
- ReconTree の段階的タスク消化と相性が悪い（一括追加 vs 順次追加）
- Recon Queue 方式なら自然な停止条件がある（Pending=0 → 終了）

### なぜ ReconTree を共有状態にするか

- HTTPAgent の発見を Main が即座に参照可能
- Main が RECON INTEL で状況を把握し、攻撃戦略を立てられる
- 将来の AttackAgent も同じ ReconTree を参照できる

## 次のフェーズ: AttackAgent + AttackDataTree

この Issue の後、以下の拡張を予定:

- **AttackAgent**: Main が spawn する攻撃用 SubAgent（SQLi exploit, credential dump 等）
- **AttackDataTree**: ReconTree を拡張し、CVE/Credential/攻撃試行結果を追跡
- **NmapAgent**: Main から nmap 実行を分離（純粋 Coordinator 化）
