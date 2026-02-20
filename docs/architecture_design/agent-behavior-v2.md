# エージェント行動改善 — システムプロンプト v2 + Signal C 削除

## 概要

Brain の行動品質を改善する 3 つの変更:

1. **ASSESSMENT WORKFLOW**: nmap 結果 → 侵入シナリオ作成を明文化
2. **RESTRICTED ACTIONS**: ブルートフォース・DoS はユーザー指示まで禁止
3. **Signal C 削除**: コマンド繰り返し検知を完全撤廃

## 1. ASSESSMENT WORKFLOW

### 背景

現状の Brain は nmap 結果を受けると web 偵察（nikto → curl → SQLi）に一直線に走り、
発見した全サービスを俯瞰した攻撃計画を立てない。

### 変更内容

`SECURITY ASSESSMENT GUIDELINES` の直後に以下を追加:

```
ASSESSMENT WORKFLOW:
After initial reconnaissance (nmap -A -sC or equivalent), you MUST follow this sequence:

1. RECORD: Use "memory" action to record all discovered services, ports, and versions
2. ANALYZE: Use "think" action to create a prioritized attack scenario considering
   ALL discovered services — not just web. Evaluate:
   - Known CVEs for discovered service versions
   - Default credentials or misconfigurations
   - Service-specific attack vectors (SMB, FTP, SSH, RDP, database, etc.)
   - Web application attack surface (if applicable)
3. PLAN: Record the attack plan with "memory" action (type: note),
   listing targets in priority order (most likely to succeed first)
4. EXECUTE: Carry out targeted verification per service, starting with
   the highest-priority target

Do NOT skip steps 1-3. Always analyze the full attack surface before
diving into individual service enumeration.
```

### 期待される効果

- nmap 後に Brain が全サービスを考慮した攻撃計画を立てる
- web 一辺倒ではなく、FTP, SMB, SSH 等も並行して調査
- memory に攻撃計画が記録されるため、途中経過が可視化される

## 2. RESTRICTED ACTIONS

### 背景

Brain がブルートフォース（hydra 等）や DoS 的手法を自律的に提案・実行する
可能性がある。これらはサービス停止やアカウントロックアウトを引き起こすため、
ユーザーが明示的に指示するまで禁止すべき。

### 変更内容

`ASSESSMENT WORKFLOW` の直後に以下を追加:

```
RESTRICTED ACTIONS (require explicit user instruction):
The following actions must NOT be executed or proposed unless the security
professional explicitly requests them:
- Brute force attacks (hydra, medusa, patator, john, hashcat, etc.)
- Denial of Service or resource exhaustion testing
- Account lockout testing
- Credential stuffing

These actions can cause service disruption or account lockout.
Wait for the security professional to explicitly instruct you before
attempting any of these techniques.
```

### 期待される効果

- Brain が自律的にブルートフォースを仕掛けない
- ユーザーが「hydra で試して」と指示した場合のみ実行/提案
- サービス停止事故の防止

## 3. Signal C 削除（コマンド繰り返し検知の撤廃）

### 背景

現状の Signal C は「直近5コマンドで同じバイナリが3回以上」で発火する。
しかし curl で異なる URL を調査している正当な場面でも誤検知する:

```
curl http://target/login       ← exit 0, 有用
curl http://target/admin       ← exit 0, 有用
curl http://target/api/users   ← Signal C 発火 → 失敗判定（誤検知）
```

### 方針転換の理由

当初は Signal C を AND 条件化（失敗時のみ発火）する予定だったが、
以下の理由から **完全削除** に方針変更:

1. **同じ LLM（Opus 4.6）を使用** — Claude Code はルールベースの繰り返し検知なしで
   動作しており、同じモデルを使う pentecter でも不要
2. **コマンド履歴は Brain に渡している** — `history []commandEntry` で直近の実行結果を
   コンテキストに含めているため、モデルが自身で「同じコマンドを繰り返している」と
   判断できる
3. **Signal A + B で十分** — 同じコマンドで失敗を繰り返せば exit code（Signal A）や
   出力パターン（Signal B）で検出され、`consecutiveFailures` が増加してストール検知が発動する
4. **SubTask のガードレールは MaxTurns で十分** — 自律実行のループ防止は
   ターン数上限で既に縛っている

### 変更内容

Signal C に関連するコードを完全削除:

```
変更前:
  evaluateResult() = Signal A + Signal B + Signal C → consecutiveFailures

変更後:
  evaluateResult() = Signal A + Signal B → consecutiveFailures
```

### 削除対象

- `isCommandRepetition()` 関数
- `evaluateResult()` 内の Signal C 呼び出し
- `commandEntry` の `Command` フィールド（履歴保持は Brain コンテキスト用に残すが、
  Signal C 用のバイナリ抽出ロジックは削除）
- Signal C 関連のテストケース

### テスト

- `TestEvaluateResult_NoSignalC_SuccessfulRepetition`: curl 3回成功 → 失敗判定されないこと（Signal A/B で成功なので通過）
- `TestEvaluateResult_NoSignalC_FailedRepetition`: nmap 3回失敗 → Signal A/B で失敗判定されること（Signal C 不要）
- 既存の `TestEvaluateResult_*` テストから Signal C 関連アサーションを削除

## プロンプト全体の変更箇所まとめ

```
systemPromptBase の構造:

  AUTHORIZATION CONTEXT:     （変更なし）
  YOUR ROLE:                 （変更なし）
  RESPONSE FORMAT:           （#50 で check_task 削除）
  ACTION TYPES:              （#50 で check_task 削除）
  SECURITY ASSESSMENT GUIDELINES:  （変更なし）
+ ASSESSMENT WORKFLOW:       （新規追加）
+ RESTRICTED ACTIONS:        （新規追加）
  USER INTERACTION:          （変更なし）
  LANGUAGE:                  （変更なし）
  STALL PREVENTION:          （変更なし）
  PARALLEL EXECUTION:        （#50 で完了プッシュに書き換え）
```

## 影響範囲

| ファイル | 変更内容 |
|----------|----------|
| `internal/brain/prompt.go` | ASSESSMENT WORKFLOW + RESTRICTED ACTIONS 追加 |
| `internal/agent/loop.go` | `isCommandRepetition()` 削除, `evaluateResult()` から Signal C 撤去 |
| `internal/agent/loop_test.go` | Signal C テスト削除 |
| `internal/agent/evaluate_test.go` | Signal C テストケース削除 |
