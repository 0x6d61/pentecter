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
