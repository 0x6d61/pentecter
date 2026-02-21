# Reactive ReconTree Spawn — 設計ドキュメント

## 概要

現在の ReconRunner は `initial_scans` で固定 nmap コマンドを実行し、完了後に `SpawnWebRecon` で SubAgent を起動する。この設計には以下の問題がある:

- **nmap コマンドが固定のため柔軟性がない**: ターゲットの特性に応じたスキャン戦略を選べない
- **全ポートスキャン (`-p-`) は遅い**: 数分〜十数分かかり、その間メイン LLM がブロックされる
- **LLM の判断力が活用されていない**: nmap のオプション選択は LLM の得意分野

**新設計**: LLM が自由にスキャン戦略を選び、`evaluateResult` が新 HTTP ポートを検出するたびに SubAgent を自動 spawn する「リアクティブモデル」に移行する。

## 前提

- ReconRunner は既に Phase 0（nmap 自動実行）と Phase 1（Web Recon SubAgent による ffuf/curl）を実装済み
- 設計ドキュメント: `docs/architecture_design/recon-runner.md`
- ReconTree によるポート/エンドポイント/vhost の構造的追跡が稼働中
- Raw output は `memory/<host>/raw/` に保存済み

## 現行アーキテクチャ

```
ReconRunner.RunInitialScans() ← 固定 nmap (-oX - 保証)
    ↓ XML パーサーで ReconTree にポート追加
ReconRunner.SpawnWebRecon()   ← HTTP ポートに SubAgent 自動 spawn
    ↓
メイン LLM 開始（ReconTree populated）
```

### 問題点

1. **固定コマンド**: `nmap -p- -sV -Pn -oX - {target}` は全ポートスキャンで遅い
2. **直列実行**: nmap 完了までメイン LLM が待機（攻撃開始が遅れる）
3. **戦略の硬直**: top-100 → 全ポートという段階的アプローチが取れない
4. **コンテキスト無視**: ターゲットの OS/サービスに応じた nmap オプション調整ができない

## 新アーキテクチャ: リアクティブ spawn

```
LLM 開始（ReconTree 空）
  ↓ LLM が nmap 実行（ASSESSMENT WORKFLOW が誘導）
evaluateResult()
  ↓ DetectAndParse → ReconTree にポート追加
  ↓ 新規 HTTP ポート検出？ → SubAgent 自動 spawn
LLM の次ターン（SubAgent と並列で攻撃フェーズへ）
  ...LLM が追加 nmap 実行 → 新ポート発見 → SubAgent 追加 spawn
```

### トリガー条件

- `evaluateResult` 後に `EndpointEnum == StatusPending` な HTTP ポートが存在
- spawn すると `StatusInProgress` になるため二重 spawn しない
- 既に SubAgent が動いているポートには spawn しない

### サイクル例

```
LLM: nmap --top-ports 100 -sV -Pn -oX - target  (数秒)
  → port 22, 80, 443 発見
  → SubAgent(80) spawn, SubAgent(443) spawn
LLM: SSH 攻撃開始（SubAgent と並列）
LLM: nmap -p- -sV -Pn -oX - target  (全ポート、数分)
  → port 8080 追加発見
  → SubAgent(8080) spawn
LLM: 8080 のサービスも考慮した攻撃を継続
```

**メリット:**
- LLM は top-ports を先に実行して数秒で攻撃開始できる
- 全ポートスキャンはバックグラウンドで並列実行
- 新ポートが見つかるたびに SubAgent が自動的に追加される

## 攻撃全体のサイクル: 偵察 ↔ 攻撃

ペンテストは偵察→攻撃の一方通行ではなく、**攻撃の結果が新たな偵察を駆動する**。

```
          ┌────────────────────────────┐
          ↓                            │
  [ 偵察 (RECON) ]               [ 新発見 ]
    nmap / ffuf / curl                 │
          │                            │
          ↓                            │
  [ 攻撃 (EXPLOIT) ]                   │
    SQLi / LFI / brute force ──────────┘
```

### 攻撃 → 偵察に戻る例

| 攻撃結果 | 偵察に戻る理由 |
|---|---|
| SQLi で DB ダンプ → 内部ホスト名発見 | 新ターゲットに nmap |
| LFI で設定ファイル読み取り → 別ポートのサービス発見 | そのポートをスキャン |
| SSH ブルートフォース成功 → ピボット先ネットワーク | 新セグメントを nmap |
| value_fuzz で新パスのリダイレクト発見 | そのパスを endpoint_enum |

### リアクティブ設計との統合

この設計の核心: **evaluateResult は常時稼働**。攻撃フェーズ中に LLM が nmap を回しても、
evaluateResult が新 HTTP ポートを検出すれば SubAgent が即座に spawn される。

RECON phase lock は一方通行ゲートではなく、**全タスク完了で自動解除 → 攻撃フェーズ → 新発見で再び偵察タスクが追加 → リアクティブ spawn** のサイクルを許容する。

## SubAgent 内部のサイクル

SubAgent（web recon）もリニア (1→2→3→4→5) ではなく発見駆動のサイクルにする:

```
endpoint_enum → profiling → param_fuzz → value_fuzz
     ↑                                      │
     └──── 新発見があればここに戻る ─────────┘
```

- `value_fuzz` でエンドポイントの新しいパスが見つかれば `endpoint_enum` に戻る
- `profiling` で隠しパスが見つかれば `endpoint_enum` に戻る
- パラメータ発見で新しいフォーム/API が見つかれば `value_fuzz` に進む
- 新発見がなくなった（pending == 0）ら SubAgent 終了

## 変更対象

| ファイル | 変更内容 |
|---|---|
| `internal/agent/loop.go` | `evaluateResult` に HTTP ポート新規検出 → SubAgent spawn フック追加 |
| `internal/agent/loop.go` | `Run()` の ReconRunner 呼び出し部分を簡素化（`initial_scans` 不要） |
| `internal/agent/recon_runner.go` | `RunInitialScans` 削除。`SpawnWebRecon` を `evaluateResult` から呼べるように公開 |
| `internal/agent/recon_parser.go` | nmap `-oX <file>` のファイル読み取り追加（ffuf の `-o <file>` と同様） |
| `internal/config/config.go` | `initial_scans` をオプショナルに（後方互換: 設定があれば従来通り動作） |
| SubAgent プロンプト | リニアからサイクル型に変更 |

## nmap 出力ファイル読み取り

### 背景

LLM が nmap を実行する場合、`-oX -`（stdout に XML 出力）ではなく `-oX <file>` を使う可能性がある。現在のパーサーは stdout の XML のみ対応しているため、ファイル出力にも対応する必要がある。

### 実装

ffuf の `-o <file>` と同様に、コマンドラインから出力ファイルパスを抽出して読み取る:

```go
// recon_parser.go に追加

// nmap -oX <file> のファイルパス抽出
func extractNmapOutputFile(cmdLine string) (path string, format string) {
    // -oX <file> → XML
    // -oN <file> → テキスト（Normal）
    // -oG <file> → Grepable
    // -oA <base> → 全フォーマット（<base>.xml を読む）
}

// DetectAndParse 内で使用
func (p *ReconParser) DetectAndParse(cmd string, stdout string, exitCode int) {
    // 1. stdout に XML が含まれているか → 既存ロジック
    // 2. なければ、コマンドから -oX/-oN ファイルパスを抽出
    // 3. ファイルが存在すれば読み取ってパース
}
```

### 対応フォーマット

| フラグ | フォーマット | パーサー |
|--------|------------|---------|
| `-oX -` | XML (stdout) | 既存 `ParseNmapXML()` |
| `-oX <file>` | XML (ファイル) | 既存 `ParseNmapXML()` + ファイル読み取り |
| `-oN <file>` | テキスト (ファイル) | 既存テキストパーサー + ファイル読み取り |
| `-oG <file>` | Grepable | 将来対応 |

## 後方互換

- `initial_scans` が設定されている場合は従来通り `RunInitialScans` を実行してから LLM を開始
- `initial_scans` が空 or 未設定の場合はリアクティブモードで動作（LLM が直接 nmap を実行）
- **デフォルトはリアクティブモード**（`initial_scans` なし）

```yaml
# config/config.yaml

# リアクティブモード（デフォルト）: initial_scans を設定しない
recon:
  max_parallel: 3

# 従来モード: initial_scans を設定すると固定コマンドが先に実行される
recon:
  max_parallel: 3
  initial_scans:
    - "nmap -p- -sV -Pn -oX - {target}"
    - "nmap -sU --top-ports 1000 -sV -Pn -oX - {target}"
```

### 判定ロジック

```go
func (r *ReconRunner) Start() {
    if len(r.config.InitialScans) > 0 {
        // 従来モード: 固定スキャン → SpawnWebRecon → LLM 開始
        r.RunInitialScans()
        r.SpawnWebRecon()
    }
    // リアクティブモード: LLM が直接実行
    // evaluateResult 内で自動 spawn
}
```

## evaluateResult のフック設計

```go
func (l *Loop) evaluateResult(cmd string, stdout string, exitCode int) {
    // 既存: DetectAndParse でツール出力をパース → ReconTree 更新
    l.parser.DetectAndParse(cmd, stdout, exitCode)

    // 新規: HTTP ポートの新規検出チェック
    newHTTPPorts := l.tree.GetPendingHTTPPorts()
    for _, port := range newHTTPPorts {
        if port.EndpointEnum == StatusPending {
            // SubAgent を spawn（二重 spawn 防止: StatusInProgress に変更）
            l.reconRunner.SpawnWebReconForPort(port)
        }
    }
}
```

### 二重 spawn 防止

- `SpawnWebReconForPort` は最初に `EndpointEnum` を `StatusInProgress` に変更
- `evaluateResult` は `StatusPending` のポートのみ対象
- `max_parallel` 制限を超える場合はキューに入れ、空きが出たら spawn

## 実装順序

1. `recon_parser.go` に nmap `-oX <file>` のファイル読み取りを追加
2. `recon_runner.go` の `SpawnWebRecon` をポート単位で呼び出せるように `SpawnWebReconForPort` を公開
3. `loop.go` の `evaluateResult` に HTTP ポート新規検出 → SubAgent spawn フックを追加
4. `loop.go` の `Run()` で `initial_scans` が空の場合のリアクティブモードを実装
5. SubAgent プロンプトをリニアからサイクル型に変更
6. `config.go` の `initial_scans` をオプショナルに変更
7. 各ステップでユニットテストを追加

## 設計根拠

### なぜ LLM にスキャン戦略を任せるか

- **段階的スキャン**: top-ports → 全ポートという戦略を LLM が判断できる
- **文脈依存**: ターゲットの OS やサービスに応じて nmap オプションを調整できる
- **速度**: top-100 は数秒で完了し、すぐに攻撃フェーズに入れる
- **柔軟性**: UDP スキャン、特定ポート帯のスキャン等を LLM が状況に応じて選択

### なぜ SubAgent spawn を evaluateResult に組み込むか

- **即応性**: HTTP ポートが見つかった瞬間に web recon が始まる
- **コード量最小**: 既存の `evaluateResult` → `DetectAndParse` フローに数行追加するだけ
- **二重 spawn 防止が容易**: ReconTree の StatusPending チェックで自然に防げる
- **後方互換**: `RunInitialScans` と `evaluateResult` の両方から同じ `SpawnWebReconForPort` を呼べる

### なぜ SubAgent をサイクル型にするか

- **発見駆動**: リニアだと profiling で見つけた隠しパスを endpoint_enum に戻して探索できない
- **網羅性**: 新発見 → 再探索のループで見落としを減らせる
- **自然な終了条件**: 新発見がなくなったら終了（pending == 0）
