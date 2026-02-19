# TUI インタラクション設計

## 概要

TUI のユーザー操作・コマンド・選択UI の設計。

## コマンド一覧

| コマンド | 説明 |
|---------|------|
| `/model` | LLM プロバイダー/モデルの選択・切り替え |
| `/approve` | Auto-approve の ON/OFF 切り替え |
| `/target <host>` | ターゲットの追加 |
| `<IP>` | IP アドレス入力でターゲット追加 |
| 自然言語 | AI エージェントへの指示 |

## 選択UI

`/model` や `/approve` を引数なしで実行した場合、テキスト入力ではなく対話的な選択UIを表示する。

### 動作

```
> /approve

Auto-approve (current: OFF):
  ● ON — auto-approve all commands
    OFF — require approval
[↑↓] Move  [Enter] Select  [Esc] Cancel
```

### キー操作

| キー | 動作 |
|------|------|
| `↑` / `↓` | 選択肢を移動 |
| `Enter` | 選択を確定し、コールバックを実行 |
| `Esc` | キャンセルして通常モードに戻る |

### 実装

- `Model.inputMode` で `InputNormal` / `InputSelect` を管理
- `InputSelect` 時はテキスト入力を無効化し、選択UI を input bar に描画
- `showSelect(title, options, callback)` メソッドで選択UIを起動
- 後方互換: `/approve on` `/approve off` のテキスト指定も引き続き動作

## コマンドサジェスト

入力フィールドで `/` を入力すると、利用可能なコマンドをオートコンプリート候補として表示。
右矢印キーでサジェストを確定。

登録済みサジェスト: `/model`, `/approve`, `/target`

## Proposal（承認ゲート）

承認が必要なコマンドは PROPOSAL ボックスとして表示:

| キー | 動作 |
|------|------|
| `y` | 承認 → コマンドを実行 |
| `n` | 拒否 → Brain に「ユーザーが拒否した」と伝える |
| `e` | 編集 → コマンドを input bar にコピーして編集可能にする |

## 関連ファイル

- `internal/tui/model.go` — Model struct、InputMode、SelectOption
- `internal/tui/update.go` — コマンド処理、選択UI のキー操作
- `internal/tui/view.go` — 選択UI のレンダリング
