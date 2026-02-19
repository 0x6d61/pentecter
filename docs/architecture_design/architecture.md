# Pentecter — システムアーキテクチャ設計書

## 1. コアコンセプト

| 項目 | 内容 |
|---|---|
| **名称** | `Pentecter`（Penetration + Detector + Specter） |
| **役割** | 自律型ペネトレーションテストエージェント（TUIベース） |
| **スタック** | Go (Golang 1.23+), Bubble Tea (TUI), Anthropic/OpenAI API (Brain) |
| **デプロイ** | 単一スタティックバイナリ / Docker (Kali Linux ベース) |

---

## 2. アーキテクチャ概要

### A. The Brain（LLM インターフェース）
- **役割**: 意思決定者。OSを直接操作しない。
- **入力**: 現在のグラフ状態 + ツール出力履歴
- **出力**: JSON アクションプラン

```json
{
  "thought": "Port 80 is open. I should check for common CMS.",
  "action": "run_tool",
  "tool": "wpscan",
  "args": ["--url", "http://target.com/", "--enumerate", "u"]
}
```

### B. The TUI（Bubble Tea）
- **モデル**: アプリケーション全状態を保持
- **ビュー構成**:
  1. **ターゲットリスト**: 左ペイン — 発見済みホスト一覧とステータス
  2. **メインコンソール**: 右ペイン — 選択中ターゲットのセッションログ
  3. **プロポーザルバー**: AI提案のApproval表示
  4. **ログ**: Brain の思考過程 + ツール生出力のストリーム
- **コマンド**: ツール実行の非同期メッセージパッシング

### C. The Hands（ツールラッパー）
- **パターン**: `os/exec` 経由のコマンドパターン実装
- **サブエージェント**:
  - 重い処理（Nmap フルスキャン、SQLMap）は独立 Goroutine で実行
  - Go Channel（`chan ToolResult`）で通信
  - メイン TUI はブロックされない

---

## 3. ディレクトリ構造

```
/pentecter
  /cmd
    /pentecter       # メインエントリポイント
  /internal
    /agent           # オーケストレータ＆ループロジック
    /brain           # LLM クライアント（Anthropic/OpenAI）
    /graph           # ナレッジグラフ（メモリ）
    /tools           # ツールラッパー（nmap, sqlmap, msf）
    /tui             # Bubble Tea モデル＆ビュー
  /pkg
    /schema          # 共有 JSON 構造体
  /docs              # 設計ドキュメント（本ディレクトリ）
```

---

## 4. 自律レベル定義

| レベル | 定義 | Pentecter の方針 |
|---|---|---|
| Level 1 | 全操作に承認必須 | 低速・安全 |
| Level 2 | 偵察は自動、攻撃は承認 | - |
| **Level 2.5** | **偵察は自動、重要アクションは提案→承認** | **採用** |
| Level 3 | 全操作自動 | 危険 |

---

## 5. 実装フェーズ

| フェーズ | 名称 | 内容 |
|---|---|---|
| **Phase 1** | The Shell | 基本 Bubble Tea TUI（Commander Console） |
| **Phase 2** | The Hands | `tools.Nmap` ラッパー実装、チャネル経由の結果受信 |
| **Phase 3** | The Brain | Claude API 接続、JSON コマンドパース |
| **Phase 4** | The Loop | Brain → Action → Tool → Result → Brain の完全ループ |
