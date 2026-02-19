# Brain コンテキスト設計

## 概要

Brain（LLM）が各ターンで受け取るコンテキスト情報の設計。
適切な判断のために、ターゲット状態・コマンド履歴・ユーザー指示を構造化して渡す。

## Brain Input 構造

```go
type Input struct {
    TargetSnapshot string   // ターゲットの現在状態（JSON）
    ToolOutput     string   // 直前のツール出力（truncated）
    LastCommand    string   // 直前に実行したコマンド
    LastExitCode   int      // 直前の exit code
    CommandHistory string   // 直近5件のコマンド履歴
    UserMessage    string   // ユーザーからの指示
}
```

## プロンプト構成

Brain に渡されるユーザープロンプトは以下のセクションで構成される:

```
## Authorized Target State
{host, status, entities, memory のJSON}

## Last Command
`nmap -sV 10.0.0.5` → exit code: 0

## Last Assessment Output
{truncated tool output}

## Recent Command History (last 5)
1. `nmap -sV 10.0.0.5` → exit 0
2. `nc -w 3 10.0.0.5 6200` → exit 1
3. `echo -e "USER test:)\nPASS test" | nc 10.0.0.5 21` → exit 0

## Security Professional's Instruction (PRIORITY)
{ユーザーメッセージ — 存在する場合のみ}
```

## コマンド履歴

- Loop struct 内に直近10件の `commandEntry` を保持
- Brain には直近5件を簡潔なフォーマットで渡す
- 各エントリ: コマンド文字列、exit code、タイムスタンプ
- 目的: Brain が「何を試して何が失敗したか」を把握し、同じ失敗を繰り返さない

## ユーザーメッセージの優先度

- ユーザーメッセージが存在する場合、ヘッダーに `(PRIORITY)` を付与
- 末尾の指示を「Address the professional's instruction first」に変更
- システムプロンプトに `USER INTERACTION` セクションを追加し、ユーザー指示の優先を明記

## システムプロンプトの設計原則

1. **共通事項のみ記載** — 個別の脆弱性（vsftpd backdoor 等）は書かない
2. **ツール一覧は動的** — Registry から読み込んだツール名を `buildSystemPrompt()` で注入
3. **登録外ツールも許可** — 「You may also use any other tools available in the environment」
4. **ユーザー優先** — `USER INTERACTION` セクションでユーザー指示の最優先を明示

## 関連ファイル

- `internal/brain/brain.go` — Input struct 定義
- `internal/brain/prompt.go` — システムプロンプト + buildPrompt
- `internal/agent/loop.go` — コマンド履歴管理、Brain への Input 構築
