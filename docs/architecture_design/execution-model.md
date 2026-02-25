# コマンド実行モデル

## 概要

pentecter の Brain（LLM）が生成するコマンドの実行環境の決定方式。

## 実行フロー

```
Registry に登録済み？
  ├── YES + docker 設定あり → Docker コンテナで実行
  ├── YES + docker 設定なし → ホスト（自プロセス）で実行
  └── NO（未登録ツール）   → ホスト（自プロセス）で実行
```

「ホスト」= pentecter が動いている環境:
- 本番: ホスト OS
- デモ: pentecter コンテナ内

## Proposal（承認ゲート）

### デフォルト動作
- Docker 実行ツール → 自動実行（サンドボックス隔離）
- ホスト実行ツール → 要承認（Proposal）
- 未登録ツール → 要承認（Proposal）
- `proposal_required: false` 明示 → 自動実行（curl 等の信頼済みツール）
- `proposal_required: true` 明示 → 常に要承認

### グローバル Auto-Approve

`--auto-approve` フラグまたは TUI の `/approve on` コマンドで有効化。
有効時は全コマンドが無条件で自動実行される。

## ツール定義（tools/*.yaml）

各ツールの実行方式は YAML で定義:

```yaml
name: nmap
docker:
  image: instrumentisto/nmap
  network: host
  fallback: true      # Docker 不可時にホスト実行にフォールバック
timeout: 600
proposal_required: false  # 省略可（Docker ありのデフォルト: false）
```

### フィールド一覧

| フィールド | 説明 |
|-----------|------|
| name | コマンドの先頭ワードと一致する識別子 |
| docker.image | Docker イメージ名 |
| docker.network | ネットワークモード（デフォルト: host） |
| docker.fallback | Docker 不可時にホスト実行するか |
| timeout | 実行タイムアウト（秒） |
| proposal_required | 承認要否の明示指定（省略時はDocker有無で自動判定） |

## デモ環境

デモ環境（docker-compose）では pentecter 自体がコンテナ内で動作する。
Docker-in-Docker は使わず、コンテナ内にインストールされたツールで直接実行する。

デモ Dockerfile には以下のツールがインストール済み:
- nmap, nmap-scripts（ポートスキャン）
- nikto（Web 脆弱性スキャン）
- curl（HTTP リクエスト）
- netcat-openbsd（バックドア接続、リバースシェル）
- python3（exploit スクリプト実行）
- hydra（ブルートフォース）
- openssh-client（SSH 接続）
- socat（リスナー、ポート転送）
- bind-tools（DNS 偵察）

## Agent Loop の失敗検知と自律制御

### 失敗検知の3シグナル

Agent Loop はコマンド実行後に `evaluateResult()` で以下の3つのシグナルを評価し、失敗を検知する。
いずれか1つでも該当すれば「失敗」と判定し、`consecutiveFailures` カウンターをインクリメントする。

| シグナル | 判定条件 | 実装 |
|----------|----------|------|
| **Signal A: exit code** | `exitCode != 0` | 非ゼロ exit code は即失敗 |
| **Signal B: 出力パターンマッチ** | 出力に失敗パターン文字列が含まれる | `isFailedOutput()` で大文字小文字を区別しない部分一致 |
| **Signal C: コマンド繰り返し** | 直近5件で同一バイナリが3回以上使用 | `isCommandRepetition()` でバイナリ名を抽出して集計 |

#### Signal B のパターン一覧

ネットワークエラー系:
- `0 hosts up`, `Host seems down`, `host is down`
- `No route to host`, `Connection refused`, `Connection timed out`
- `Network is unreachable`, `Name or service not known`, `couldn't connect to host`

プログラムエラー系:
- `SyntaxError`, `command not found`, `No such file or directory`
- `Permission denied`, `Traceback (most recent call last)`
- `ModuleNotFoundError`, `ImportError`, `panic:`, `NameError`, `Segmentation fault`

特殊:
- 出力が空文字列の場合も失敗と判定
- 先頭が `Error:` で始まる場合も失敗と判定

#### Signal C の繰り返し検知

`extractBinary()` がコマンド文字列の先頭ワードからバイナリ名を抽出する（パス部分を除去）。
直近5件の履歴で同一バイナリが3回以上出現した場合、繰り返しと判定し TUI にログを出力する。

```
例: "nmap -sV 10.0.0.5" → バイナリ名 "nmap"
    "/usr/bin/nmap -sV"  → バイナリ名 "nmap"
```

### 連続失敗時のスタール（stall）検知

`consecutiveFailures` が `maxConsecutiveFailures`（デフォルト: 3）に達すると:

1. `EventStalled` イベントを TUI に送信
2. ターゲットのステータスを `PAUSED` に変更
3. ユーザーからのメッセージをブロッキングで待機（`waitForUserMsg()`）
4. ユーザー入力を受け取ったら `consecutiveFailures` をリセットし、ループを再開

### コマンド結果サマリー

`buildCommandSummary()` がコマンド実行結果を1行のサマリーに変換する。

- 成功時: `exit 0 (42 lines)` — exit code と出力行数
- 失敗時: `exit 1: Connection refused` — exit code と出力の1行目（最大80文字）

### ユーザーメッセージの即時処理

ユーザーがチャット入力で送信したメッセージは、以下のタイミングでドレイン（取得）される:

| タイミング | 関数 | 説明 |
|-----------|------|------|
| **ループ先頭** | `drainUserMsg()` | 毎ターン冒頭でノンブロッキング取得 |
| **stall 時** | `waitForUserMsg()` | 連続失敗後にブロッキング待機 |

`drainUserMsg()` は `select` + `default` パターンを使い、メッセージが無ければ空文字を即座に返す。
メッセージがある場合、`skillsReg` が設定されていればスキル呼び出し（`/skill-name`）を展開してから返す。

取得したユーザーメッセージは `brain.Input.UserMessage` にセットされ、Brain のプロンプトで
`## Security Professional's Instruction (PRIORITY)` セクションとして渡される。

### ターンカウンター（turnCount）

Agent Loop はターンごとにカウンターをインクリメントし、`brain.Input.TurnCount` として Brain に渡す。
Brain のプロンプトには `## Turn` セクションが追加され、自律ループの進行度を把握できる。
10ターンを超えた場合、自律性の警告メッセージが Brain に伝えられる（詳細は `brain-context.md` を参照）。
