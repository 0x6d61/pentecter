# Hybrid TUI — ANSI Scroll Region Layout

## 概要

Bubble Tea フルスクリーンモデルからの脱却後、readline ベースのハイブリッド TUI に移行した。
本設計では、**入力欄をターミナル最下部に固定表示**するために ANSI スクロールリージョンを活用する。

Claude Code と同様に、出力エリアと入力エリアを完全に分離し、入力は常にターミナル下部に固定される。

## 目的

1. **入力の固定表示**: 出力がゼロ行でも、大量のログが流れていても、入力欄は常にターミナル最下部
2. **出力の自動スクロール**: 出力エリア内でのみスクロールが発生し、入力欄は影響を受けない
3. **高頻度出力への耐性**: ffuf 等の大量出力がイベントキューを圧迫しても、キーボード入力は遅延しない

## レイアウト

```
行 1 〜 h-4: 出力エリア（ANSI スクロールリージョン）
             ターミナルが自動スクロールを管理
行 h-3:     ────────────────────── (上部仕切り線)
行 h-2:     > █                    (入力行 — readline 管理)
行 h-1:     ────────────────────── (下部仕切り線)
行 h:       10.0.0.5 [SCANNING]  anthropic/claude-sonnet-4-6 (ステータス行)
```

### 固定 4 行

ターミナル最下部の 4 行は常に固定:
- **上部仕切り線** (h-3): `─` の繰り返し。ターミナル幅全体
- **入力行** (h-2): readline が管理。`> ` プロンプト + ユーザー入力 + モード表示
- **下部仕切り線** (h-1): `─` の繰り返し
- **ステータス行** (h): ターゲット、モデル情報

### スクロールリージョン

```
\033[1;{h-4}r
```

このエスケープシーケンスにより、行 1 〜 h-4 がスクロール対象になる。
h-3 以降は固定され、出力がスクロールリージョンに印字されるとリージョン内だけがスクロールする。

## 入力プロンプトデザイン

Claude Code に完全に倣い、シンプルな水平線 + `>` のみ:

### 通常モード
```
──────────────────────────────────
> █
──────────────────────────────────
10.0.0.5 [SCANNING]  anthropic/claude-sonnet-4-6
```

### Proposal モード
```
──────────────────────────────────
approve? [y/n/e] > █
──────────────────────────────────
```

### Select モード
```
──────────────────────────────────
select [1-3/q] > █
──────────────────────────────────
```

### スピナー表示中
```
──────────────────────────────────
⠋ Thinking... > █
──────────────────────────────────
```

## ANSI エスケープシーケンス

| シーケンス | 用途 |
|-----------|------|
| `\033[1;{n}r` | スクロールリージョン設定（行 1 〜 n） |
| `\0337` | DEC カーソル保存 |
| `\0338` | DEC カーソル復元 |
| `\033[{row};{col}H` | カーソル絶対移動 |
| `\033[K` | 行末までクリア |
| `\033[2J` | 画面全クリア |
| `\033[H` | カーソルをホームポジション (1,1) に移動 |

### DEC Save/Restore vs CSI Save/Restore

readline は内部で CSI 形式（`\033[s` / `\033[u`）を使用する可能性がある。
衝突を避けるため、出力エリアへの書き込みには **DEC 形式**（`\0337` / `\0338`）を使用する。

## goroutine アーキテクチャ

```
goroutine A (main)     readline.Readline() ブロッキングループ
                       → 入力処理、コマンドディスパッチ

goroutine B (events)   agentEvents チャネル受信
                       → handleAgentEvent() で Blocks 更新
                       → writeToOutputArea() でスクロールリージョンに印字

goroutine C (spinner)  100ms ティッカー
                       → readline プロンプトを更新（スピナーフレーム）
                       → ステータス行を更新

goroutine D (resize)   500ms ポーリング
                       → ターミナルサイズ変更検出
                       → スクロールリージョン再設定 + 固定フレーム再描画
```

## 主要メソッド

### `setupLayout()`

起動時およびリサイズ時に呼ばれる。

```
1. ターミナルサイズ (width, height) を取得
2. scrollRegionEnd = height - 4 を計算
3. \033[2J\033[H で画面クリア
4. \033[1;{scrollRegionEnd}r でスクロールリージョン設定
5. drawFixedFrame() で固定 4 行を描画
6. カーソルを入力行に移動
```

### `drawFixedFrame()`

固定フレーム（仕切り線 + ステータス行）を描画する。

```
1. \0337 でカーソル位置保存（DEC 形式）
2. カーソルを行 h-3 に移動
3. ────── を描画（上部仕切り線）
4. 行 h-2 はスキップ（readline が管理）
5. カーソルを行 h-1 に移動
6. ────── を描画（下部仕切り線）
7. カーソルを行 h に移動
8. ステータステキストを描画
9. \0338 でカーソル位置復元
```

### `writeToOutputArea(text string)`

スクロールリージョンにテキストを出力する。
全 goroutine から呼ばれるため、`outputMu` で排他制御する。

```
1. outputMu.Lock()
2. \0337 でカーソル位置保存
3. カーソルをスクロールリージョン最終行に移動
4. テキストを出力（改行がスクロールを引き起こす）
5. \0338 でカーソル位置復元
6. outputMu.Unlock()
```

**重要**: `rl.Stdout()` は使用しない。直接 `os.Stdout` に書き込み、
readline のプロンプト再描画は `rl.Refresh()` で行う。

### `buildPrompt()`

```go
// 通常モード: "> "
// Proposal: "approve? [y/n/e] > "
// Select:   "select [1-N/q] > "
// Spinner:  "⠋ Thinking... > "
```

仕切り線は `drawFixedFrame()` が管理するため、プロンプトには含めない。

## リサイズ処理

```
1. 新しい width, height を取得
2. 前回と異なる場合:
   a. scrollRegionEnd を再計算
   b. \033[1;{scrollRegionEnd}r でスクロールリージョン再設定
   c. drawFixedFrame() で固定フレーム再描画
   d. readline プロンプトをリフレッシュ
```

Windows では SIGWINCH が利用不可のため、`term.GetSize()` で 500ms ポーリングする。

## テスト時の動作

`testWriter` が設定されている場合:
- ANSI エスケープシーケンスは出力しない
- `writeToOutputArea()` は `testWriter` に直接書き込む
- `setupLayout()` / `drawFixedFrame()` はスキップ
- テストは出力内容のみを検証する

## スレッドセーフティ

| 共有リソース | 保護方法 |
|-------------|---------|
| `target.Blocks` | `App.mu sync.Mutex` |
| `spinnerActive/spinnerIdx` | `atomic.Bool` / `atomic.Int32` |
| スクロールリージョンへの書き込み | `App.outputMu sync.Mutex` |
| `target.Proposal` | 既存の `target.mu sync.RWMutex` |
| `termHeight/width` | `App.mu` で保護 |

## Windows 互換性

- **ANSI エスケープ**: Windows Terminal はデフォルトで VT100 対応
- **スクロールリージョン**: Windows Terminal / ConHost で動作確認済み
- **DEC Save/Restore**: Windows Terminal で対応
- **リサイズ検出**: `term.GetSize()` ポーリング（SIGWINCH 非対応）
- **改行**: readline が `\r\n` を内部処理

## 参考: Claude Code の実装

Claude Code は React Ink（Node.js）+ Yoga レイアウトエンジンを使用。
Go にはこれに相当するライブラリが存在しないため、ANSI スクロールリージョンで同等の効果を実現する。
