# Pentecter — UI 設計仕様書

## 1. コアコンセプト：Commander Console

| 項目 | 内容 |
|---|---|
| **スタイル** | Slack ライクな 2 ペインレイアウト（リスト + メインビュー） |
| **哲学** | "Autonomous but Controllable"（自律的、しかし制御可能） |
| **自律レベル** | Level 2.5 — AI が提案し、人間が重要ステップを承認/拒否する |

---

## 2. スクリーンレイアウト

```
+----------------+---------------------------------------------------+
| TARGETS (List) | MAIN CONSOLE (Active Session View)                |
| [ALL] Global   |                                                   |
|                | [15:00] AI: Port 80 open (Apache 2.4.49).         |
| [#1] 10.0.0.5  | [15:01] AI: Vulnerable to CVE-2021-41773?         |
| [#2] 10.0.0.8⚡| [15:01] AI: Planning exploit...                   |
| [#3] 10.0.0.12 |                                                   |
|                | > [PROPOSAL] Run Metasploit (exploit/multi/http/) |
|                | > Target: 10.0.0.8, LHOST: 10.0.0.2              |
|                | > APPROVE? [y/N/edit]                             |
|                |                                                   |
+----------------+---------------------------------------------------+
| INPUT > _ (AI へのチャット / コマンドオーバーライド)               |
+------------------------------------------------------------------------+
```

### ペイン説明

| ペイン | 役割 |
|---|---|
| **左: TARGETS** | 発見済みホストの一覧。ステータスアイコン付き。上下キーで選択切替。 |
| **右: MAIN CONSOLE** | 選択中ターゲットのセッションログ（スクロール可）。AI の思考・ツール出力・Proposal を表示。 |
| **下: INPUT** | AI への自然言語指示またはコマンドを直接入力。 |

---

## 3. ターゲットステータスアイコン

| アイコン | ステータス | 意味 |
|---|---|---|
| `○` | IDLE | 未着手 |
| `◎` | SCANNING | 偵察中 |
| `▶` | RUNNING | 攻撃実行中 |
| `⏸` | PAUSED | Approval 待ち |
| `⚡` | PWNED | 侵害成功 |
| `✗` | FAILED | 失敗 |

---

## 4. インタラクションフロー

### 通常フロー
1. **AI Thinking**: 思考ステップをログに表示（"Scanning...", "Analyzing..."）
2. **Tool Execution**: ツールの生出力をリアルタイムにストリーミング
3. **AI Analysis**: 結果を解釈し次の行動を計画

### 重要アクション（Proposal フロー）
```
AI が重要アクションを検出
    ↓
[PROPOSAL] ブロックをコンソールに表示
    ↓
ユーザー入力を待機
    ↓
[y] → 承認して実行
[n] → スキップして次の計画へ
[e] → Input に内容をコピーして編集後に送信
```

### チャットインターフェース
- 自然言語で AI に指示を送れる
- 例: `"Port 445 だけに集中して"` → AI がプランを更新
- 例: `"スキャンを止めて"` → AI が現在タスクをキャンセル
- 例: `use exploit/windows/smb/ms17_010_psexec` → コマンドを直接オーバーライド

---

## 5. キーバインド

| キー | 動作 |
|---|---|
| `Tab` | フォーカス切替（リスト → コンソール → 入力 → ...） |
| `↑↓` / `j/k` | リスト選択 or コンソールスクロール（フォーカス依存） |
| `y` | Proposal 承認（Proposal 表示中） |
| `n` | Proposal 拒否（Proposal 表示中） |
| `e` | Proposal を編集モードで Input に展開 |
| `Enter` | 入力送信 |
| `Ctrl+C` | 終了 |

---

## 6. 技術実装詳細

| コンポーネント | ライブラリ | 用途 |
|---|---|---|
| ターゲットリスト | `github.com/charmbracelet/bubbles/list` | 左ペインのナビゲーション |
| セッションログ | `github.com/charmbracelet/bubbles/viewport` | スクロール可能なログ表示 |
| 入力ボックス | `github.com/charmbracelet/bubbles/textinput` | チャット/コマンド入力 |
| スタイリング | `github.com/charmbracelet/lipgloss` | TUI レイアウト・色 |

### ターゲット状態モデル
各ターゲットは独立した状態を持つ：
```go
type Target struct {
    ID       int
    IP       string
    Status   Status      // IDLE / SCANNING / RUNNING / PAUSED / PWNED / FAILED
    Logs     []LogEntry  // セッションログ（per-target）
    Proposal *Proposal   // 承認待ちアクション（nil = なし）
}
```

### ログエントリ形式
```
[15:04:05] [AI  ]  Apache 2.4.49 detected — CVE-2021-41773 may apply
[15:04:06] [TOOL]  nmap -sV -p 80 10.0.0.5
[15:04:08] [SYS ]  Session started
[15:04:09] [USER]  Focus on port 445 only.
```
