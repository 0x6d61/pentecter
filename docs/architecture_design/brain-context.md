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
    TurnCount      int      // 現在のターン番号（1始まり）
}
```

### TurnCount フィールド

`TurnCount` は Agent Loop のメインループが何回目のイテレーション（ターン）かを示す値。
1始まりで、Brain が `Think()` を呼ばれるたびにインクリメントされる。

**用途:**
- Brain が自律ループの進行度を把握するため
- 長時間の自律実行を検知し、ユーザーへの確認を促すため
- TUI のターン区切り表示にも使用される

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

### Turn セクション

TurnCount が 1 以上の場合、プロンプトに `## Turn` セクションが追加される:

```
## Turn
This is turn 5 of the assessment.
```

10ターンを超えた場合は、自律性の警告メッセージが追加される:

```
## Turn
This is turn 15 of the assessment.
You have been running autonomously for many turns. Consider if you should propose actions for human review.
```

TurnCount が 0（未設定）の場合、Turn セクションは生成されない。

**設計意図:**
- Brain が「何ターン自律で動いているか」を認識できるようにする
- 10ターン超で `propose` アクションの利用を促し、人間の監視を担保する
- 無限ループ防止の補助的な役割を果たす

## コマンド履歴

- Loop struct 内に直近10件の `commandEntry` を保持
- Brain には直近5件を簡潔なフォーマットで渡す
- 各エントリ: コマンド文字列、exit code、タイムスタンプ
- 目的: Brain が「何を試して何が失敗したか」を把握し、同じ失敗を繰り返さない

## ユーザーメッセージの優先度

- ユーザーメッセージが存在する場合、ヘッダーに `(PRIORITY)` を付与
- 末尾の指示を「Address the professional's instruction first. Respond with JSON only.」に変更
- システムプロンプトに `USER INTERACTION` セクションを追加し、ユーザー指示の優先を明記

### USER INTERACTION セクションの内容

システムプロンプト内の `USER INTERACTION` セクションは以下の3点を Brain に指示する:

1. **即時対応**: `Security Professional's Instruction` が存在する場合、thought と action で必ず言及する
2. **think アクション活用**: 質問や分析要求にはコマンド実行不要の `think` アクションで応答可能
3. **優先順位の明確化**: セキュリティ専門家の入力は、自律アセスメントより常に優先される

```
USER INTERACTION:
- When a "Security Professional's Instruction" is present, you MUST address it in your thought and action
- Use "think" action to respond to questions or provide analysis when no command is needed
- The security professional's input always takes priority over autonomous assessment
```

## システムプロンプトの設計原則

1. **共通事項のみ記載** — 個別の脆弱性（vsftpd backdoor 等）は書かない
2. **ツール一覧は動的** — Registry から読み込んだツール名を `buildSystemPrompt()` で注入
3. **登録外ツールも許可** — 「You may also use any other tools available in the environment」
4. **ユーザー優先** — `USER INTERACTION` セクションでユーザー指示の最優先を明示

## スタール防止プロンプト

システムプロンプトには `STALL PREVENTION` セクションが含まれ、Brain が無限ループに陥るのを防ぐ:

- 同じまたは類似のコマンドを結果が無いまま繰り返さない
- 2〜3回のスキャンでホストが到達不能なら `complete` で終了
- `0 hosts up` や全ポートフィルタの場合、ターゲットはオフラインとして完了扱い
- nmap が失敗したら curl, ping 等の別ツールを試す
- 同種のスキャンの無限ループに入らない

これはプロンプトレベルの防止策であり、Agent Loop 側の `evaluateResult()`（exit code / パターンマッチ / コマンド繰り返し検知）と組み合わせて二重に防御する。

## 関連ファイル

- `internal/brain/brain.go` — Input struct 定義（TurnCount フィールド含む）
- `internal/brain/prompt.go` — システムプロンプト + buildPrompt（Turn セクション生成）
- `internal/agent/loop.go` — コマンド履歴管理、Brain への Input 構築、evaluateResult
- `internal/agent/event.go` — EventType 定義（EventTurnStart, EventCommandResult）
