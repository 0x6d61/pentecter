# Parameter Value Fuzzing — 設計ドキュメント

## 概要

ReconRunner の Web Recon SubAgent において、FFUF によるパラメーター発見（Phase 1）の後に、発見されたパラメーターの **バリューファジング（Phase 2）** を自動実行する機能。

ペネトレーションテストにおいて、Web アプリケーションの脆弱性の大半はテンプレート化可能であり、差異はパラメーターとセキュリティ機構の有無に過ぎない。バリューファジングにより IDOR、SQLi、パストラバーサル、SSTI 等の足がかりを自動的に発見する。

## 前提

- ReconRunner は既に Phase 0（nmap 自動実行）と Phase 1（Web Recon SubAgent による ffuf/curl）を実装済み
- 設計ドキュメント: `docs/architecture_design/recon-runner.md`
- ReconTree によるポート/エンドポイント/vhost の構造的追跡が稼働中
- Raw output は `memory/<host>/raw/` に保存済み

## フロー

```
Phase 1: パラメーター発見（既存）
  ffuf -w params.txt -u http://target/endpoint?FUZZ=test
  → 発見: id, file, search, page ...

Phase 2: バリューファジング（本設計の対象）
  発見された各パラメーターに対して:
  
  ┌─ ベースラインリクエスト: GET /endpoint?id=1 → 200, 1234 bytes, 50ms
  │
  ├─ numeric:  id=0, id=2, id=-1, id=99999
  ├─ sqli:     id=', id=", id=1' OR 1=1--
  ├─ path:     id=../etc/passwd, id=....//etc/passwd
  ├─ ssti:     id={{7*7}}, id=${7*7}
  ├─ cmdi:     id=;id, id=|id
  └─ xss:      id=<script>alert(1)</script>
  
  ↓ 異常検出: id=2 で異なるユーザーデータ返却（IDOR 疑い）
  ↓ 異常検出: id=' で 500 + MySQL エラー（SQLi 疑い）
  
  → ReconTree に finding として追加
  → Raw output は memory/<host>/raw/ に保存済み
```

## 設計方針

### 1. 必須ファジングカテゴリ（コード定義 + SubAgent プロンプト注入）

AI の自律性と網羅性を両立するため、**必須テストカテゴリをコード側で定義**し、SubAgent プロンプトに注入する。AI は各カテゴリ内の具体的なペイロードをパラメーター名の文脈に応じて選定する。

```go
type FuzzCategory struct {
    Name        string // カテゴリ識別子
    Description string // SubAgent プロンプト用の説明
}

var MinFuzzCategories = []FuzzCategory{
    {Name: "numeric",   Description: "IDOR/権限昇格: 連番ID (0, 1, 2, -1, 99999)"},
    {Name: "sqli",      Description: "SQL Injection: 引用符、コメント、ブーリアンロジック"},
    {Name: "path",      Description: "Path Traversal: ../ シーケンス、エンコードバリアント"},
    {Name: "ssti",      Description: "Template Injection: {{7*7}}, ${7*7}, #{7*7}"},
    {Name: "cmdi",      Description: "Command Injection: ;id, |id, `id`, $(id)"},
    {Name: "xss_probe", Description: "XSS: script タグ、イベントハンドラ、javascript: URI"},
}
```

**ルール:**
- SubAgent は全カテゴリを **必ず** テストする（MANDATORY）
- 各カテゴリで AI が 2〜5 個のペイロードを選定
- パラメーター名の文脈に応じた追加ペイロードも AI の判断で投入可

### 2. 検出基準（4軸）

| 検出軸 | 担当 | 詳細 |
|--------|------|------|
| ステータスコード変化 | コード（パーサー） | ベースラインと比較、差異があれば flag |
| コンテンツ長変化 | コード（パーサー） | ベースライン ±10% 以上で flag |
| レスポンス時間 | コード（パーサー） | ベースラインの 5x 以上遅延で flag（Time-based injection 検出） |
| レスポンスボディ解析 | AI（SubAgent） | エラーメッセージ、情報漏洩、挙動変化の意味的判断 |

**役割分担の理由:**
- ステータスコード・コンテンツ長・時間は機械的に比較可能 → コード側で自動検出
- ボディの意味理解（「これは MySQL エラー出力」「これは別ユーザーのデータ」）→ AI の強み
- コード側の自動検出により、AI が見落としても拾える安全網になる

### 3. SubAgent プロンプトフロー

発見された各パラメーターに対して SubAgent が実行するフロー:

```
1. ベースラインリクエスト送信（正常値）
   curl -s -w "\n%{http_code} %{size_download} %{time_total}" http://target/endpoint?id=1

2. 各必須カテゴリについて:
   a. パラメーター名から適切なペイロードを 2-5 個選定
   b. 各ペイロードで curl 実行（ステータスコード・サイズ・時間を記録）
   c. ベースラインと比較

3. 異常を検出した場合:
   → finding として報告（evidence 付き）
   → ReconTree に追加
```

SubAgent へのプロンプト注入イメージ:

```
You discovered parameter "{param}" on {method} {endpoint}.
You MUST test ALL of these categories against this parameter:
  [numeric, sqli, path, ssti, cmdi, xss_probe]

For each category:
1. Choose 2-5 payloads appropriate for the parameter context
2. Send requests with curl, recording: status code, content-length, response time
3. Compare against baseline (normal value response)
4. Report any anomaly with evidence

Additionally, based on the parameter name "{param}",
add any context-specific payloads you think are worth testing.
```

### 4. ReconTree 統合

Finding レベルでノードを追加する（パラメーター単位のノードは不要）:

```
target (10.0.0.5)
├── 80/tcp (http)
│   ├── /login [200]
│   │   └── finding: param "username" — SQLi suspect (500 on single quote)
│   ├── /profile [200]
│   │   └── finding: param "id" — IDOR suspect (different content on id=2)
│   └── /search [200]
│       └── finding: param "q" — SSTI suspect (49 in response for {{7*7}})
```

Raw output は既に `memory/<host>/raw/` に保存されるため、AI は後から詳細を参照可能。

### 5. 実装場所

| 変更対象 | 内容 |
|----------|------|
| `internal/agent/fuzz_categories.go`（新規） | `FuzzCategory` 型と `MinFuzzCategories` 定義 |
| `internal/agent/recon_runner.go` | SubAgent プロンプトに Phase 2 指示を追加 |
| `internal/agent/recon_parser.go` | レスポンスベースライン比較（status, size, time）追加 |
| `internal/agent/recon_tree.go` | Finding ノード追加メソッド |
| `config/config.example.yaml` | `fuzz_categories` カスタマイズオプション（将来） |

## 実装順序（未着手）

1. `FuzzCategory` 型と `MinFuzzCategories` を定義
2. SubAgent プロンプトテンプレートに Phase 2 指示を追加
3. レスポンスベースライン比較を `recon_parser.go` に追加
4. ReconTree に finding ノード追加
5. 脆弱なテストサーバーで統合テスト

## 設計根拠

### なぜ AI にペイロード選定を任せるか

- パラメーター名の意味を理解できる（`id` → 数値、`file` → パス、`q` → テキスト）
- テンプレート化しにくいエッジケースにも対応可能
- 静的リストでは網羅できない文脈依存のペイロードを生成できる

### なぜ必須カテゴリをコードで強制するか

- AI に完全に任せると特定カテゴリをスキップするリスクがある
- 「SQLi だけ試して満足」を防ぐ網羅性の保証
- プロンプトで MANDATORY と書いても LLM は無視することがある → コード側で制御

### なぜ Finding レベルのノードで十分か

- パラメーター単位のノードは粒度が細かすぎて ReconTree が肥大化する
- Raw output が保存されているので、必要に応じて後から詳細を参照可能
- メイン LLM が finding を見れば、次の攻撃ステップを判断できる
