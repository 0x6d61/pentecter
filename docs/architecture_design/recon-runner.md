# ReconRunner — 自動偵察ハイブリッド設計

## 概要

RECON フェーズを LLM に依存せず構造的に制御する。
nmap は固定コマンドで自動実行、HTTP の web recon は SubAgent が自律的に実行。
メイン LLM は nmap 完了後すぐに攻撃フェーズに入り、SubAgent の偵察結果をリアルタイムで受け取る。

## 背景・課題

- LLM が RECON QUEUE の MANDATORY 指示を無視して ANALYZE に飛ぶ
- nmap の出力形式（XML vs テキスト）が LLM 次第で不安定
- 全ポート・全エンドポイントの網羅的スキャンが保証できない

## アーキテクチャ

```
Target 追加
  │
  ├─ [Phase 0: Fixed] nmap 自動実行
  │   ├─ TCP: nmap -p- -sV -Pn -oX - {target}
  │   └─ UDP: nmap -sU --top-ports 1000 -sV -Pn -oX - {target}
  │   → XML パーサーで ReconTree にポート/バナー追加
  │   → Raw output を memory/<host>/raw/ に保存
  │
  ├─ [Phase 1: SubAgent] HTTP ポートごとに web recon
  │   → SubAgent (SubBrain) を spawn
  │   → SubAgent が自律的に ffuf/curl を実行
  │   │   - endpoint_enum: ffuf でディレクトリ列挙（再帰的）
  │   │   - vhost_discovery: ffuf で仮想ホスト列挙
  │   │   - param_fuzz: ffuf でパラメータ列挙
  │   │   - profiling: curl でレスポンス確認
  │   → SubAgent の出力をパーサーで ReconTree に反映
  │   → 新エンドポイント発見 → 新 pending タスク自動追加
  │   → 全 HTTP recon 完了で SubAgent 終了
  │
  └─ [並列: Main LLM] nmap 完了後すぐ起動
      → 非 HTTP サービス攻撃（MySQL, SSH, SMB 等）
      → 既知 CVE → 即 exploit
      → SubAgent の更新が各ターンで参照可能
      → web recon 結果が届き次第、攻撃面拡大
```

## Config

```yaml
recon:
  max_parallel: 3
  initial_scans:
    - "nmap -p- -sV -Pn -oX - {target}"
    - "nmap -sU --top-ports 1000 -sV -Pn -oX - {target}"
```

- `{target}` はホスト名に自動置換
- `initial_scans` は順次実行（TCP → UDP）
- `max_parallel` は SubAgent の並列数制限

## コンポーネント

### ReconRunner

Loop.Run() 内で起動される偵察オーケストレーター。

```go
type ReconRunner struct {
    tree      *ReconTree
    runner    *tools.CommandRunner
    subBrain  brain.Brain         // SubAgent 用
    events    chan Event
    target    *Target
    memDir    string              // raw output 保存先
}
```

**責務:**
1. `initial_scans` を実行し、nmap XML をパース
2. HTTP ポートを検出したら SubAgent を spawn
3. SubAgent の出力を ReconTree に反映
4. TUI にログを emit
5. 全 pending 完了で終了

### SubAgent の web recon

SubAgent には以下のプロンプトを与える：

```
あなたは {host}:{port} の HTTP サービスに対する web 偵察エージェントです。
以下のタスクを順番に実行してください：

1. endpoint_enum: ffuf でディレクトリ列挙（再帰的に深掘り）
2. vhost_discovery: ffuf でサブドメイン列挙
3. 発見した各エンドポイントに対して:
   - param_fuzz: パラメータ列挙
   - profiling: curl でレスポンス確認

ffuf は必ず -of json オプションを付けてください。
発見した全エンドポイントを再帰的に掘り下げ、結果が 0 件になるまで続けてください。
```

SubAgent は自律的にコマンドを生成・実行。技術スタックに応じて
wordlist や `-fs` を動的に調整できる。

### nmap 固定コマンドのメリット

- `-oX -` が保証 → XML パーサーが確実に動く
- 全ポート網羅 → 見落としなし
- LLM の判断に依存しない → 再現性がある

## フロー詳細

### Phase 0: Initial Scan

```
Loop.Run()
  → initial_scans を順次実行
  → 各コマンドの出力を ParseNmapXML() でパース
  → ReconTree にポート追加
  → TUI にログ表示（"Initial scan: nmap -p- ..."）
  → ユーザーは並行してプロンプト入力可能
```

### Phase 1: Web Recon (SubAgent)

```
HTTP ポートが見つかった場合:
  → SubAgent を spawn（max_parallel 制限内）
  → SubAgent が ffuf/curl を自律実行
  → Loop が SubAgent の出力を DetectAndParse() でパース
  → ReconTree 更新（新エンドポイント → 新 pending タスク）
  → SubAgent は pending == 0 まで継続
```

### Main LLM Loop (並列)

```
nmap 完了後すぐ起動:
  → ReconTree の状態を参照（各ターン）
  → RECON 情報セクション: 発見済みポート/サービス一覧
  → 非 HTTP サービスから攻撃開始
  → SubAgent 完了通知が来たら web 攻撃面も考慮
```

## TUI 表示

- `/recontree` で進捗確認（既存）
- Initial scan 中: `[RECON] Running nmap TCP full scan...`
- SubAgent 動作中: `[RECON] Web recon on :80 — 5/12 tasks complete`
- SubAgent 完了: `[RECON] Web recon complete on :80`

## 将来の拡張

- **nmap --script 自動実行**: サービスに応じた NSE スクリプトを自動選択
  - vuln カテゴリ: `nmap --script vuln -p{port} {target}`
  - サービス固有: `nmap --script smb-enum* -p445 {target}`
- **レスポンスベース適応**: SubAgent が WAF 検出時に wordlist/速度を調整
- **認証済みスキャン**: credentials 発見後に認証付き ffuf を実行

## 実装ファイル一覧

| ファイル | 操作 | 内容 |
|----------|------|------|
| `internal/agent/recon_runner.go` | 新規 | ReconRunner 本体 |
| `internal/agent/recon_runner_test.go` | 新規 | テスト |
| `internal/config/config.go` | 修正 | `InitialScans` フィールド追加 |
| `internal/config/config_test.go` | 修正 | テスト追加 |
| `internal/agent/loop.go` | 修正 | Run() で ReconRunner 起動 |
| `internal/agent/recon_parser.go` | 修正 | nmap テキストパーサー追加 |
| `internal/agent/recon_parser_test.go` | 修正 | テスト追加 |
| `internal/brain/prompt.go` | 修正 | RECON QUEUE を偵察情報セクションに変更 |
| `config/config.example.yaml` | 修正 | `initial_scans` 追加 |
