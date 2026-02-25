# Pentecter — UI 設計仕様書

## 1. コアコンセプト：Hybrid Terminal UI

| 項目 | 内容 |
|---|---|
| **スタイル** | Claude Code 風ハイブリッドターミナルUI |
| **哲学** | "Autonomous but Controllable"（自律的、しかし制御可能） |
| **自律レベル** | Level 2.5 — AI が提案し、人間が重要ステップを承認/拒否する |

---

## 2. スクリーンレイアウト

### 通常状態

出力はターミナルの上部にスクロールし、入力枠とステータスは下部に固定される。

```
  ✻ Completed in 3s
  Based on nmap results, port 80 is running Apache...

  ● nmap -sV -p 80 10.0.0.5
    ⎿  PORT  STATE SERVICE VERSION
       80/tcp open  http    Apache 2.4.49
       … +12 lines (ctrl+o)

  ⠋ Thinking...

├──────────────────────────────────────────────────────────┤
│ > █
╰──────────────────────────────────────────────────────────╯
  10.0.0.5 [RUNNING]  anthropic/claude-sonnet-4-6
```

### Proposal（承認待ち）

```
  ╭── ⚠ PROPOSAL ────────────────────────────────────╮
  │ Run nmap service version scan                     │
  │ Tool: nmap -sV -p 80,443 10.0.0.5                │
  │                                                   │
  │ [y] Approve  [n] Reject  [e] Edit                 │
  ╰───────────────────────────────────────────────────╯

├──────────────────────────────────────────────────────────┤
│ approve? [y/n/e] > █
╰──────────────────────────────────────────────────────────╯
  10.0.0.5 [PAUSED]  anthropic/claude-sonnet-4-6
```

### 選択UI（/model, /approve, /targets）

```
  Select provider:
    1. anthropic
    2. openai
    3. ollama

├──────────────────────────────────────────────────────────┤
│ select [1-3/q] > █
╰──────────────────────────────────────────────────────────╯
  10.0.0.5 [RUNNING]  anthropic/claude-sonnet-4-6
```

### 起動直後（ターゲットなし）

```
  ⚡ PENTECTER — Autonomous Penetration Testing Agent

  Enter an IP address or domain to begin
    e.g. 10.0.0.5, example.com

  Commands:
    /targets, /model, /approve, /recontree, /skip-recon

├──────────────────────────────────────────────────────────┤
│ > █
╰──────────────────────────────────────────────────────────╯
  anthropic/claude-sonnet-4-6
```

---

## 3. 入力モード

| モード | プロンプト表示 | トリガー |
|--------|--------------|---------|
| Normal | `│ > ` | 通常状態 |
| Proposal | `│ approve? [y/n/e] > ` | EventProposal 受信 |
| Select | `│ select [1-N/q] > ` | /model, /approve, /targets 実行 |
| ConfirmQuit | `│ Quit Pentecter? [y/n] > ` | Ctrl+C |

---

## 4. ターゲットステータスアイコン

| アイコン | ステータス | 意味 |
|---|---|---|
| `○` | IDLE | 未着手 |
| `◎` | SCANNING | 偵察中 |
| `▶` | RUNNING | 攻撃実行中 |
| `⏸` | PAUSED | Approval 待ち |
| `⚡` | PWNED | 侵害成功 |
| `✗` | FAILED | 失敗 |

---

## 5. インタラクションフロー

### 通常フロー
1. **AI Thinking**: スピナー表示（`⠋ Thinking...`）
2. **Tool Execution**: コマンド出力をリアルタイムにストリーミング
3. **AI Analysis**: 結果を解釈し次の行動を計画

### 重要アクション（Proposal フロー）
```
AI が重要アクションを検出
    ↓
PROPOSAL ボックスを出力エリアに表示
    ↓
入力プロンプトが「approve? [y/n/e] >」に変化
    ↓
[y] → 承認して実行
[n] → スキップして次の計画へ
[e] → コマンドを表示して編集方法を提示
```

### チャットインターフェース
- 自然言語で AI に指示を送れる
- 例: `"Port 445 だけに集中して"` → AI がプランを更新
- 例: `"192.168.81.1をスキャンして"` → ターゲット自動追加 + 指示送信

---

## 6. コマンド一覧

| コマンド | 説明 |
|---------|------|
| `/model` | LLM プロバイダー/モデルの選択・切り替え |
| `/approve` | Auto-approve の ON/OFF 切り替え |
| `/targets` | ターゲット一覧表示と切り替え |
| `/target <host>` | ターゲットの追加 |
| `/recontree` | 偵察ツリーの ASCII 表示 |
| `/skip-recon` | RECON フェーズロックの手動解除 |
| `/fold` | コマンド出力の折りたたみ切り替え |
| `/status` | ステータスライン表示 |
| `Ctrl+O` | 折りたたみ切り替え（グローバル） |
| `Ctrl+C` | 終了確認 |

---

## 7. 技術実装

### goroutine 構成

```
goroutine A (main)       readline.Readline() ブロッキングループ
                         → 入力処理、コマンドディスパッチ

goroutine B (events)     agentEvents チャネル受信
                         → handleAgentEvent() で Blocks 更新
                         → 完了ブロックを rl.Stdout() 経由で即座に印字

goroutine C (spinner)    100ms ティッカー
                         → スピナーフレーム更新 → readline prompt 再描画

goroutine D (resize)     500ms ティッカー
                         → term.GetSize() でターミナル幅ポーリング（Windows対応）
```

### ライブラリ

| 用途 | ライブラリ |
|------|-----------|
| 入力管理 | `github.com/ergochat/readline` |
| Markdown レンダリング | `github.com/charmbracelet/glamour` |
| スタイリング | `github.com/charmbracelet/lipgloss` |
| ターミナル情報 | `golang.org/x/term` |

### スレッドセーフティ

| 共有リソース | 保護方法 |
|-------------|---------|
| `target.Blocks` | `App.mu sync.Mutex` |
| スピナー状態 | `atomic.Bool` / `atomic.Int32` |
| stdout | `rl.Stdout()` 経由（readline 内部で同期） |

---

## 8. 関連ファイル

| ファイル | 役割 |
|---------|------|
| `internal/tui/app.go` | App 構造体、Run() メインループ、フレーム描画 |
| `internal/tui/input.go` | InputMode 状態マシン、コマンドパース、target 追加 |
| `internal/tui/output.go` | スピナー goroutine、折りたたみ、Proposal/Status 表示 |
| `internal/tui/events.go` | イベント消費 goroutine、handleAgentEvent() |
| `internal/tui/commands.go` | /model, /approve, /targets 等のハンドラ |
| `internal/tui/render.go` | ブロックレンダリング関数群 |
| `internal/tui/styles.go` | カラーパレット、lipgloss スタイル定義 |
