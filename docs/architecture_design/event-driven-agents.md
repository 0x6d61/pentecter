# Event-Driven Agent Architecture v3

## 背景と課題

### 現状 (v2: Reactive Recon Spawn)
```
MainAgent (自律ループ: Think → Act → Evaluate → repeat)
  └─ HTTPReconAgent (SubAgent: webfuzz で web 偵察)
```

### 問題点
1. **Rabbit hole**: MainAgent が毎ターン「次何する？」を考え、似たコマンドを繰り返す
2. **Phase gate**: HTTPRecon 待ちで MainAgent がブロック（何もできない時間）
3. **責務過多**: MainAgent が推論+偵察+攻撃をすべて実行
4. **LLM コスト**: 新情報がなくても毎ターン Brain.Think() を呼ぶ
5. **データ欠損**: vhost/パラメータ/Finding が AttackDataTree に記録されない

## 設計方針

**MainAgent は自律ループを廃止し、イベント駆動のコーディネーターにする。**

- 新しい情報が来た時だけ判断する（Think on Event）
- コマンドは一切実行しない。実行は常に専門エージェントに委譲
- ルールベースで処理できるものは Brain を呼ばない
- Brain は「攻撃計画」「方針転換」など判断が必要な場面でのみ使用

---

## エージェント構成

```
MainCoordinator (イベント駆動 — コマンド実行しない)
  ├─ ReconAgent       nmap + HackTricks 調査
  ├─ WebReconAgent    webfuzz (endpoint/param/vhost)
  ├─ WebAttackAgent   Web 脆弱性攻撃
  └─ AttackAgent      インフラ攻撃 (FTP/SSH/MySQL...)
```

### MainCoordinator

**役割**: 判断と委譲のみ。

```go
for event := range domainEvents {
    switch e := event.(type) {

    // --- ルールベース（Brain 不要） ---
    case PortDiscovered:
        if isHTTP(e.Service) {
            spawn(WebReconAgent, e.Host, e.Port)
        }
        spawn(ReconAgent.Research, e.Port, e.Service, e.Banner)

    case WebReconComplete:
        spawn(WebAttackAgent, e.Host, e.Port, e.Endpoints, e.Params)

    // --- Brain 判断（戦略的決定） ---
    // NOTE: Brain.Think(ctx, input) は LLM 応答待ち（数秒〜数十秒）でブロックするため、
    // イベントループ内で同期呼び出しすると他のイベント処理が停止する。
    // Brain 呼び出しは別 goroutine に委譲し、結果を DomainEvent として返す。
    // ルールベース処理はインラインのまま（即時応答）。
    // goroutine 数は brainSem（maxBrainInflight=2）で制限する（§ Brain in-flight 制御 参照）。
    case ReconComplete:
        brainSem <- struct{}{}
        go func() {
            defer func() { <-brainSem }()
            plan, err := brain.Think(ctx, buildAttackPlan(e))
            if err != nil { return }
            select {
            case domainEvents <- PlanReady{Tasks: plan.Tasks}:
            case <-ctx.Done():
            }
        }()

    case PlanReady:
        for _, task := range e.Tasks {
            spawn(task.AgentType, task.Args...)
        }

    case AgentStalled:
        brainSem <- struct{}{}
        go func() {
            defer func() { <-brainSem }()
            strategy, err := brain.Think(ctx, buildPivotPlan(e))
            if err != nil { return }
            select {
            case domainEvents <- PivotReady{Strategy: strategy}:
            case <-ctx.Done():
            }
        }()

    case PivotReady:
        respawnWith(e.Strategy)

    case VulnFound:
        updateTree(e)
        if e.Severity == "high" && needsEscalation(e) {
            brainSem <- struct{}{}
            go func() {
                defer func() { <-brainSem }()
                plan, err := brain.Think(ctx, buildEscalationPlan(e))
                if err != nil { return }
                select {
                case domainEvents <- EscalationReady{Plan: plan}:
                case <-ctx.Done():
                }
            }()
        }

    case UserInput:
        brainSem <- struct{}{}
        go func() {
            defer func() { <-brainSem }()
            decision, err := brain.Think(ctx, buildUserResponse(e))
            if err != nil { return }
            select {
            case domainEvents <- UserDecisionReady{Decision: decision}:
            case <-ctx.Done():
            }
        }()
    }
}
```

**Brain 呼び出し基準**:
- ルールで判断できる → 呼ばない（ポート → エージェント spawn）
- 戦略判断が必要 → 呼ぶ（攻撃計画、方針転換、ユーザー対話）

### ReconAgent

**役割**: ターゲットの偵察。nmap + HackTricks 知識ベース調査。

**入力**: ターゲット IP/ホスト名
**使用ツール**: nmap, HackTricks ファイル読み取り

**処理フロー**:
```
1. nmap -sV -sC -p- -Pn -T4 {target}
2. ポート/サービス/バナーを解析
3. 各サービスについて HackTricks を調査:
   - ポート番号 → `config/config.yaml` の `knowledge` セクションで設定されたパス
   - バナー/バージョン → 既知 CVE の特定
   - 攻撃手法の整理
4. 調査結果を構造化して emit
```

**出力イベント**:
- `PortDiscovered{Port, Service, Banner, Version}`
- `ServiceIdentified{Port, Service, CVEs[], AttackVectors[], Notes}`
- `ReconComplete{Host, Ports[], Summary}`

**Brain の使い方**:
- nmap 結果の解釈
- HackTricks のどのページが関連するか判断
- 追加スキャンが必要か判断（UDP スキャン、スクリプトスキャン等）

### WebReconAgent (既存 HTTPReconAgent の発展)

**役割**: HTTP サービスの偵察。エンドポイント/パラメータ/vhost 発見。

**入力**: ホスト + ポート
**使用ツール**: webfuzz (dir/param/vhost)

**処理フロー**:
```
1. webfuzz dir: エンドポイント列挙
2. 発見したエンドポイントごとに:
   a. webfuzz param: パラメータ発見
   b. webfuzz vhost: 仮想ホスト発見
3. 再帰: 新しいディレクトリが見つかれば 1 に戻る
```

**出力イベント**:
- `EndpointFound{Host, Port, Path, Status}`
- `ParamFound{Host, Port, Path, Name, ParamType}`
- `VhostFound{Host, Port, VhostName}`
- `WebReconComplete{Host, Port, Endpoints[], Params[], Vhosts[]}`

### WebAttackAgent

**役割**: Web アプリケーション脆弱性の攻撃。

**入力**: ホスト + ポート + エンドポイント + パラメータ一覧
**使用ツール**: curl, webfuzz (value fuzz), sqlmap, 手動ペイロード

**処理フロー**:
```
1. Brain がエンドポイント+パラメータを分析
2. パラメータごとに攻撃カテゴリを選択:
   - SQLi (error-based, blind, time-based)
   - XSS (reflected, stored)
   - SSTI (Jinja2, Twig, etc.)
   - Command Injection
   - Path Traversal
   - IDOR
3. ペイロードを生成・実行
4. レスポンスを分析して脆弱性を判定
```

**出力イベント**:
- `VulnFound{Host, Port, Path, Param, VulnType, Evidence, Severity}`
- `ExploitSuccess{Host, Port, VulnType, Impact, Detail}`
- `CredentialFound{Host, Port, Service, Username, Password}`

### AttackAgent

**役割**: 非 HTTP サービスの攻撃。

**入力**: ポート + サービス + バナー + HackTricks 調査結果
**使用ツール**: hydra, sqlmap, ftp, ssh, nc, サービス固有ツール

**処理フロー**:
```
1. ReconAgent の HackTricks 調査結果を参照
2. サービスに応じた攻撃:
   - FTP: 匿名ログイン、既知バックドア (vsftpd 2.3.4)
   - SSH: デフォルト認証、鍵ベース攻撃
   - MySQL: 認証なしアクセス、UDF
   - SMB: 共有列挙、EternalBlue
3. 発見した認証情報で他サービスへの横展開を提案
```

**出力イベント**:
- `VulnFound{...}`
- `CredentialFound{...}`
- `AccessGained{Host, Port, Service, Level}`

---

## イベントシステム

### イベント型一覧

```go
// 偵察イベント
type PortDiscovered struct {
    Host, Service, Banner, Version string
    Port                           int
}

type ServiceIdentified struct {
    Host, Service string
    Port          int
    CVEs          []string
    AttackVectors []string
    Notes         string // HackTricks からの知見
}

type ReconComplete struct {
    Host    string
    Ports   []PortInfo
    Summary string // 偵察結果の要約（Brain 向け）
}

// Web 偵察イベント
type EndpointFound struct {
    Host, Path string
    Port, Status int
}

type ParamFound struct {
    Host, Path, Name, ParamType string
    Port                        int
}

type VhostFound struct {
    Host, VhostName string
    Port            int
}

type WebReconComplete struct {
    Host      string
    Port      int
    Endpoints []EndpointInfo
    Params    []ParamInfo
    Vhosts    []string
}

// 攻撃イベント
type VulnFound struct {
    Host, Path, Param      string
    Port                   int
    VulnType, Evidence     string
    Severity               string // critical, high, medium, low, info
}

type ExploitSuccess struct {
    Host           string
    Port           int
    VulnType       string
    Impact, Detail string
}

type CredentialFound struct {
    Host, Service, Username, Password string
    Port                              int
}

type AccessGained struct {
    Host, Service, Level string // Level: user, root, admin
    Port                 int
}

// 制御イベント
type AgentStalled struct {
    AgentID   string
    AgentType string
    Turn      int
    LastAction string
}

type AgentComplete struct {
    AgentID   string
    AgentType string
    Summary   string
}

type UserInput struct {
    Message string
}
```

### イベントフロー例

```
User: "target 172.30.0.20"

Main → spawn ReconAgent(172.30.0.20)

ReconAgent:
  nmap -sV -sC -p- 172.30.0.20
  → emit PortDiscovered(21, ftp, "vsftpd 2.3.4")
  → emit PortDiscovered(22, ssh, "OpenSSH 4.7p1")
  → emit PortDiscovered(80, http, "Apache 2.2.8")
  HackTricks: vsftpd 2.3.4 → CVE-2011-2523 backdoor
  → emit ServiceIdentified(21, ftp, cves=["CVE-2011-2523"])
  → emit ReconComplete

Main receives PortDiscovered(80, http):
  → [Rule] HTTP → spawn WebReconAgent(172.30.0.20, 80)

Main receives ServiceIdentified(21, ftp, CVE-2011-2523):
  → [Rule] Known CVE → spawn AttackAgent(172.30.0.20, 21, ftp)

Main receives PortDiscovered(22, ssh):
  → [Rule] SSH → spawn AttackAgent(172.30.0.20, 22, ssh)

WebReconAgent(port 80):
  webfuzz dir → /admin, /login, /api, /uploads
  → emit EndpointFound(/admin, 200)
  → emit EndpointFound(/login, 200)
  webfuzz param /login → username, password
  → emit ParamFound(/login, username)
  → emit ParamFound(/login, password)
  → emit WebReconComplete(port=80)

Main receives WebReconComplete:
  → [Brain] 攻撃計画: "SQLi on /login, IDOR on /api/user"
  → spawn WebAttackAgent(172.30.0.20, 80, plan)

AttackAgent(port 21, ftp):
  vsftpd 2.3.4 backdoor test
  → emit VulnFound(port=21, "backdoor", "CVE-2011-2523", critical)
  nc 172.30.0.20 6200 → shell
  → emit AccessGained(172.30.0.20, 6200, shell, root)

WebAttackAgent(port 80):
  SQLi test: /login?username=' OR 1=1--
  → emit VulnFound(port=80, /login, username, "sqli", high)
  → emit ExploitSuccess(sqli, "auth bypass")
```

---

## AttackDataTree 拡張

### 現状の不足

| 不足 | 対応 |
|------|------|
| ~~vhost タスク完了漏れ~~ | ~~CompleteTask(TaskVhostDiscov) を webfuzz vhost モード完了時に呼ぶ~~ |
| ~~パラメータ未記録~~ | ~~`AddParameter()` を TreeUpdater に追加~~ |
| ~~Finding 未記録~~ | ~~`AddFinding()` を TreeUpdater に追加~~ |
| 認証情報 | `AddCredential()` を新設 |
| HackTricks 知見 | `AddInsight()` を新設 |

### TreeUpdater インターフェース拡張

```go
// webfuzz.TreeUpdater（webfuzz パッケージ側、フラット引数）— 実装済み (#125)
type TreeUpdater interface {
    AddEndpointWithStatus(host string, port int, parentPath, newPath string, httpStatus int)
    AddVhost(parentHost string, port int, vhostName string)
    CompleteTask(host string, port int, path string, taskType int)
    AddParameter(host string, port int, path string, name string, paramType string)
    AddFinding(host string, port int, path string, param, category, evidence, severity string)
}

// AttackDataTree（agent パッケージ側、Finding 構造体）— 実装済み (#125)
// webfuzzTreeAdapter が上記フラット引数を Finding 構造体に変換してブリッジする。
func (t *AttackDataTree) AddFinding(host string, port int, path string, finding Finding)
```

> **2層パターン（webfuzz 限定）**: webfuzz パッケージは agent に依存できないため、フラット引数の
> `TreeUpdater` を定義。`webfuzzTreeAdapter`（`webfuzz_adapter.go`）が `Finding` 構造体に変換して
> `AttackDataTree.AddFinding()` を呼ぶ。webfuzz 由来の更新のみこのパターンを使う。
> Credential/Insight は webfuzz 経由でなく `AttackDataTree` を直接呼ぶため、このパターンの対象外。

```go
// 新規（未実装）— AttackDataTree に直接追加する（webfuzz.TreeUpdater には含めない）
// 理由: webfuzz.TreeUpdater は webfuzz 由来の更新に限定すべき。
//       Credential/Insight は webfuzz 以外のエージェント（AttackAgent, WebAttackAgent）が
//       直接 AttackDataTree を呼んで記録する。
func (t *AttackDataTree) AddCredential(host string, port int, cred Credential)
func (t *AttackDataTree) AddInsight(host string, port int, insight Insight)
```

> **AddFinding 実行経路の注記**:
> - `AddFinding` は TreeUpdater / AttackDataTree 両方に実装済み (#125)
> - ただし webfuzz は現在 `dir/param/vhost` モードのみ。value fuzz モードは未実装
> - value fuzz モード追加時に `AddFinding` を hitFn 内で呼ぶ実装が必要
> - WebAttackAgent が curl/手動ペイロードで Finding を記録する経路も必要

> **AddCredential / AddInsight の影響範囲**:
> - `AttackDataNode`（`attack_data_tree.go:84`）に `Credentials []Credential` / `Insights []Insight` フィールド追加が必要
> - バックアップ DTO（`AttackDataNodeDTO`, `attack_data_tree.go:1364`）にも反映
> - `RenderTree()` / `RenderIntel()` の表示対応
> - `/attackdata` TUI コマンドでの表示対応

### 新データ構造

```go
type Parameter struct {
    Name      string // パラメータ名
    Type      string // query, form, header, cookie, path
    Values    []string // 有効な値（発見済み）
}

type Credential struct {
    Service  string
    Username string
    Password string
    Source   string // "brute_force", "sqli_dump", "default", "config_leak"
}

type Insight struct {
    Source  string // "hacktricks", "nmap_script", "manual"
    Topic  string // "CVE-2011-2523", "default_credentials", etc.
    Detail string
}
```

---

## 移行計画

段階的に移行する。各ステップは独立してマージ可能。

### Phase 1: バグ修正 + TreeUpdater 拡張 ✅ 実装済み (#125)
1. ~~vhost CompleteTask 漏れ修正~~ → 実装済み
2. ~~`AddParameter()` を TreeUpdater に追加 + webfuzz param モード連携~~ → 実装済み
3. ~~`AddFinding()` を TreeUpdater + AttackDataTree に追加~~ → 実装済み
   - ⚠️ webfuzz value fuzz モード自体は未実装（`dir/param/vhost` のみ）
   - value fuzz モードで `AddFinding` を呼ぶ連携は Phase 4 (WebAttackAgent) で実装予定
4. ~~webfuzz ストリーミング化~~ → 実装済み
5. ~~テスト~~ → 実装済み

### Phase 2: ReconAgent 実装（完了）
1. ~~ReconAgent を SmartSubAgent ベースで実装~~ → 実装済み
2. ~~nmap 実行 + HackTricks 調査を ReconAgent に移管~~ → 実装済み
3. ~~MainAgent の initial_scans を ReconAgent 経由に変更~~ → 実装済み
4. ~~PortDiscovered / ServiceIdentified イベント追加~~ → 実装済み

### Phase 3: MainAgent → MainCoordinator 変換

> **工数注記**: Phase 3 は最大スコープの変更。以下が密結合しているため段階的に進める：
> - Loop の自律ループ（`loop.go:181`）
> - Brain.Think + ActionType 分岐（`loop.go:245-343`）
> - Schema（`pkg/schema/action.go`）
> - プロンプト（`internal/brain/prompt.go`）
>
> **段階的移行ステップ**:
> 1. まずドメインイベントバスを追加（既存 Loop に並行稼働）
> 2. ルールベースルーティングを追加（既存判断ロジックと共存）
> 3. 最後に自律ループを廃止

1. イベントループに書き換え（自律ループ廃止）
2. ~~ルールベースルーティング実装~~（HTTP→WebRecon, WebReconComplete→WebAttack は実装済み）
3. Brain 呼び出しをイベントトリガーに限定
4. Phase gate 廃止

### Phase 4: WebAttackAgent 実装
1. ~~WebReconComplete イベント受信で起動~~
2. パラメータ+エンドポイントベースの攻撃計画
3. VulnFound / ExploitSuccess イベント emit

### Phase 5: AttackAgent 実装
1. サービス固有攻撃ロジック
2. HackTricks 知見ベースの攻撃選択
3. 横展開提案（CredentialFound → 他サービスへ）

---

## 並行性モデル

### 2層チャネル設計

**現行**: `chan agent.Event` は TUI 表示用。emit は `select/default` でドロップ前提。
**問題**: ドメインイベント（PortDiscovered 等）はドロップ不可。

**解決策**: UI イベントとドメインイベントを分離する。

```
┌─────────────────────────────────────────────────────┐
│ UIイベント（既存）                                    │
│   chan agent.Event (buffered 512, non-blocking)      │
│   → TUI 表示用（ログ、コマンド出力、スピナー）          │
│   → ドロップ OK（select/default で溢れたら捨てる）     │
└─────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────┐
│ ドメインイベント（新規）                               │
│   chan DomainEvent (buffered 64, blocking send)      │
│   → Coordinator のルーティング用                      │
│   → PortDiscovered, WebReconComplete, PlanReady 等   │
│   → ドロップ不可（バックプレッシャーで送信側を待機）     │
└─────────────────────────────────────────────────────┘
```

### エージェント構成図

```
MainCoordinator goroutine (ドメインイベントループ)
  │
  ├─ ReconAgent goroutine ──────→ domainEvents channel (blocking)
  ├─ WebReconAgent goroutine ──→ domainEvents channel (blocking)
  ├─ WebAttackAgent goroutine ─→ domainEvents channel (blocking)
  ├─ AttackAgent goroutine ────→ domainEvents channel (blocking)
  │                                    │
  │                                    ↓
  │                             MainCoordinator が受信
  │
  └─ 全エージェント ──→ uiEvents channel (non-blocking, drop OK)
                              │
                              ↓
                         TUI が受信して表示
```

- 各エージェントは独立した goroutine で実行
- ドメインイベントは `domainEvents chan DomainEvent` に blocking send
- UI イベントは `uiEvents chan agent.Event` に non-blocking send（ドロップ許容）
- MainCoordinator は `for event := range domainEvents` で逐次処理
- Brain.Think() は別 goroutine で実行し、結果を `domainEvents` に返す（上記コード例参照）
- 複数エージェントが同時実行可能（max_parallel で制限）
- AttackDataTree への書き込みは既存の `sync.RWMutex` で保護

### Brain in-flight 制御

Brain goroutine の無制限 spawn を防ぐため、以下の制約を設ける：

- `maxBrainInflight`（default: 2）で同時 LLM 呼び出し数を制限
- セマフォ（`chan struct{}`）で制御。goroutine 起動前に acquire、完了時に release
- `domainEvents` への送信は `select { case domainEvents <- result: case <-ctx.Done(): }` でキャンセル可能にする
- イベントバースト時は後続の Brain 要求がセマフォ待ちになる（バックプレッシャー）

```go
brainSem := make(chan struct{}, maxBrainInflight) // default: 2

case ReconComplete:
    brainSem <- struct{}{} // acquire (blocks if at limit)
    go func() {
        defer func() { <-brainSem }() // release
        plan := brain.Think(ctx, buildAttackPlan(e))
        select {
        case domainEvents <- PlanReady{Tasks: plan.Tasks}:
        case <-ctx.Done():
        }
    }()
```

### マルチターゲット対応

- 現行: `Team`（`team.go:28`）がターゲットごとに `Loop` を保持
- MainCoordinator もターゲット単位で存在する（1 Target = 1 Coordinator）
- `Team` は複数 Coordinator を管理する上位レイヤー
- `AddTarget`（`team.go:66`）で新ターゲット追加時に新 Coordinator を生成

---

## TUI 表示

各エージェントの状態を TUI に表示:

```
[RECON]      nmap -sV -sC -p- 172.30.0.20    running (turn 3/50)
[WEB-RECON]  port 80: webfuzz dir /           running (turn 12/50)
[ATTACK]     port 21: vsftpd backdoor test    running (turn 2/50)
[WEB-ATTACK] port 80: SQLi on /login          pending (waiting for web-recon)
```

既存の EventSubTaskLog / EventSubTaskComplete を拡張して、
エージェント種別を表示に反映する。

### Event 種別フィールドの追加

現行の `Event` struct（`event.go`）には agent 種別フィールドがなく、
TUI は `TaskID` ベースで処理している。エージェント種別表示のため以下を追加する：

```go
// AgentKind 定数（event.go に定義）
// 既存の TaskPhase（schema/action.go:82）と同じアンダースコア区切り規約に統一する。
const (
    AgentKindRecon     = "recon"
    AgentKindWebRecon  = "web_recon"  // TaskPhase "web_recon" と一致
    AgentKindWebAttack = "web_attack"
    AgentKindAttack    = "attack"
)

// Event に追加するフィールド
type Event struct {
    // ... 既存フィールド ...
    AgentKind string // AgentKind* 定数を使用。"" = main agent
}
```

- **`EventSubTaskStart`**（`loop_tasks.go:86`）、`emitLog()`、`emitTaskComplete()` の
  すべてで `AgentKind` をセットする（TUI の表示ブロック生成は `EventSubTaskStart` で行われるため必須）
- TUI 側は `AgentKind` が空でなければ `[RECON]` 等のプレフィックスを表示
- 既存の `TaskID` ベース処理との互換性を維持（`AgentKind` は追加フィールド）
- `AgentKind` と `TaskPhase` の対応: spawn 時に `Action.TaskPhase` → `Event.AgentKind` にマッピング
