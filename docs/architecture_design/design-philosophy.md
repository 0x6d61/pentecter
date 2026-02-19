# Pentecter — 設計思想

## コアフィロソフィー

**「ユーザーの環境で動き、ユーザーが責任を持つ」**

Claude Code が直接コマンドを実行するのと同じ哲学。
Pentecter は AI の判断を実行する代理人であり、ユーザーが承認したことに責任を持つ。

---

## ツール実行モデル

### Brain が CLI コマンドを自律生成する

```json
{
  "thought": "port 80 open — run nikto for web vuln scan",
  "action": "run",
  "command": "nikto -h http://10.0.0.5/ -Tuning 1"
}
```

**なぜ args_template を使わないか:**
- ツールの CLI 仕様は変化する（curl の新オプション、nmap の新フラグ等）
- 静的テンプレートは常に陳腐化するリスクがある
- Brain は学習済みのツール知識を持っているので、自律生成に任せる方が正確
- 欲しいのは「実行結果」であって「コマンドの形式」ではない

### Docker でのツール実行（オプション）

Docker はコンテナ型のため「1プロセス」に特化している。
Metasploit（複数プロセス）や公式イメージのないツールには向かない。

**使い分け:**

| ツール | 実行方式 | 理由 |
|---|---|---|
| nmap, nikto, curl | Docker（推奨） | raw socket / 単一プロセス、隔離が容易 |
| metasploit | ホスト直接 | 複数プロセス連携が必要 |
| 自作ツール | Docker（推奨） | カスタム Dockerfile で定義 |

```yaml
# tools/nmap.yaml — Docker で実行
name: nmap
docker:
  image: instrumentisto/nmap
  fallback: true      # Docker 不可ならホスト実行にフォールバック
proposal_required: false  # Docker 実行なので自動承認（デフォルト: Docker=false, ホスト=true）

# tools/metasploit.yaml — ホスト直接実行（要承認）
name: msfconsole
binary: msfconsole
proposal_required: true   # ホスト実行なので y/n 確認（デフォルト）

# tools/curl.yaml — ホストだが信頼済みツールとして自動承認
name: curl
binary: curl
proposal_required: false  # 明示的に off にすると承認スキップ
```

---

## 承認ゲートの設計思想

**Docker = サンドボックス = 自動承認**
**ホスト直接 = ユーザー環境 = 要承認**

```
Docker 実行 → ホストへの影響ゼロ → 自動実行（Brain が run を使う）
ホスト実行  → ユーザー環境に影響 → Brain が propose を使い y/n を求める
```

Brain のシステムプロンプトにこのルールを明記することで、
Brain が自律的に適切な action を選択する。

---

## ブラックリスト

ホスト環境への破壊的操作を防ぐための最終防衛線。
Docker 実行にはブラックリストチェックを省略（隔離済みのため）。

```yaml
# config/blacklist.yaml
patterns:
  - 'rm\s+-rf\s+/'      # ルートディレクトリの再帰削除
  - 'dd\s+if='           # ディスク直接書き込み
  - 'mkfs'               # ファイルシステムフォーマット
  - '>\s*/dev/sd'        # デバイスへの直接書き込み
  - 'shutdown'
  - 'reboot'
```

---

## MCP との組み合わせ

| ツール種別 | 方式 |
|---|---|
| 学習済みメジャーツール（nmap 等） | YAML + CommandRunner |
| マイナー/カスタムツール | MCP サーバーを自作 |
| API 系（Shodan, VirusTotal） | MCP サーバー |

Brain は MCP ツールを `call_mcp` アクションで呼び出す。
MCP ツールは schema を持つため Brain が引数を自律生成できる。

---

## Agent Team（並列実行）

複数の Agent Loop を goroutine で並列実行する。
横展開（Lateral Movement）フェーズで複数ターゲットを同時攻略できる。

```
Team
  ├─ Loop[10.0.0.5] → goroutine → events → TUI
  ├─ Loop[10.0.0.8] → goroutine → events → TUI
  └─ Loop[10.0.0.12] → goroutine → events → TUI
```

TUI の左パネルにはすべてのエージェントのステータスが表示され、
選択中のエージェントのログが右パネルに表示される。

```go
type Team struct {
    loops   []*Loop
    events  chan Event   // 全 Loop のイベントを集約
}

func (t *Team) Start(ctx context.Context) {
    for _, loop := range t.loops {
        go loop.Run(ctx)   // 並列実行
    }
}
```

---

## Skills（ペンテスト手順テンプレート）

Claude Code の `/commit` スキルのように、
ペンテスト特化の手順をプロンプトテンプレートとして定義する。

```yaml
# skills/web-recon.yaml
name: web-recon
description: "Webアプリ初期偵察"
prompt: |
  対象 Web アプリの初期偵察を実施してください。
  手順: nmap（ポート確認）→ nikto（Web 脆弱性）→ CMS 確認（wpscan 等）
  対象ポート: 80, 443, 8080, 8443
  発見した脆弱性・認証情報・アーティファクトは memory に記録すること。
```

ユーザーが TUI で `/web-recon` と入力すると Brain の Think() にスキルプロンプトが追加される。

---

## Memory（ナレッジグラフ）

ツール実行結果から意味のある情報を抽出し Markdown ファイルに記録する。
Brain がコンテキストを圧迫せずに参照できる永続記憶として機能する。

```markdown
# Target: 10.0.0.5

## Vulnerabilities
- [HIGH] CVE-2021-41773: Apache 2.4.49 Path Traversal（確認済み）

## Artifacts
- /etc/passwd 取得成功
- /var/www/html/config.php に DB 接続情報

## Credentials
- MySQL: root / (no password)
- Web admin: admin / password123
```

Entity 抽出（ポート・IP・CVE・URL）より意味レベルが高い情報を
Brain が能動的に記録する仕組み。

---

## コンテキスト管理（圧迫防止）

```
ツール生出力（全行）
  ├─→ TUI ログ表示（人間が見る）
  ├─→ Log Store（全行保存、Brain がいつでも参照可能）
  ├─→ Entity 抽出 → ナレッジグラフ（構造化）
  ├─→ 切り捨てテキスト → Brain の即時コンテキスト
  │     ├ 先頭 N 行（バナー・ヘッダー）
  │     ├ [--- X 行省略 ---]
  │     └ 末尾 M 行（最終発見）
  └─→ Memory.md への記録（Brain が判断して書き込む）
```

HTTP レスポンスのような不定形出力は切り捨て戦略で対応。
Brain が「全ログを見せて」と要求したときは Log Store から取得できる。
