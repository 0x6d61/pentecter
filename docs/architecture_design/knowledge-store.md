# Knowledge Store — 内蔵ナレッジベース検索

## 概要

HackTricks 等のペンテスト知識ベースを pentecter 内に直接組み込み、Brain が `search_knowledge` / `read_knowledge` アクションで検索・参照できるようにする。

MCP 経由の外部プロセスではなく、Go ネイティブの検索を実装する。

## 動機

- HackTricks MCP サーバーは Node.js + npm + ビルドが必要 → セットアップが重い
- MCP の実態は ripgrep + readFile → Go で十分実装可能
- `git clone --depth 1` だけで使えるようにしたい
- Brain が直接知識を検索できることで、ペンテストの知識不足による無限ループを軽減

## HackTricks リポジトリ構造

```
hacktricks/
├── src/
│   ├── SUMMARY.md                          # 全記事の目次（階層構造）
│   ├── pentesting-web/                     # Webアプリテスト（86記事）
│   │   ├── sql-injection/
│   │   │   ├── README.md
│   │   │   ├── mssql-injection.md
│   │   │   └── mysql-injection/
│   │   ├── xss-cross-site-scripting/
│   │   ├── csrf-cross-site-request-forgery.md
│   │   └── ...
│   ├── network-services-pentesting/        # ネットワークサービス
│   ├── linux-hardening/
│   ├── windows-hardening/
│   ├── generic-methodologies-and-resources/
│   └── ... (20+ カテゴリ)
├── book.toml
└── README.md
```

- マークダウンファイルは `src/` 以下に階層的に配置
- ディレクトリ名がカテゴリ、ファイル名がトピック
- `SUMMARY.md` が全記事の目次（リンク一覧）

## 設計

### パッケージ: `internal/knowledge/`

```go
// store.go

// Store はナレッジベースへの検索・読み取りインターフェース
type Store struct {
    basePath string // clone 済みリポジトリの src/ ディレクトリ
}

// NewStore はナレッジベースのパスを受け取り Store を作成する。
// パスが空または存在しない場合は nil を返す（graceful skip）。
func NewStore(basePath string) *Store

// Search はクエリに一致するファイル・セクションを返す。
// 複数キーワードはAND検索。結果は関連度順にソート。
func (s *Store) Search(query string, maxResults int) []SearchResult

// ReadFile は指定パスのマークダウンファイルを読む。
// パスは basePath からの相対パス。サイズ上限付き。
func (s *Store) ReadFile(path string, maxBytes int) (string, error)

// ListCategories はトップレベルカテゴリ一覧を返す。
func (s *Store) ListCategories() []Category
```

```go
// SearchResult は検索結果1件を表す
type SearchResult struct {
    File       string   // 相対パス（例: "pentesting-web/sql-injection/README.md"）
    Title      string   // 最初の H1 ヘッダー
    Section    string   // マッチしたセクションの H2/H3 ヘッダー
    Snippet    string   // マッチ行の前後コンテキスト
    MatchCount int      // マッチ数
}

// Category はナレッジベースのカテゴリ
type Category struct {
    Name     string // ディレクトリ名
    Path     string // 相対パス
    FileCount int   // 配下のマークダウンファイル数
}
```

### 検索アルゴリズム

1. `filepath.WalkDir` で `*.md` ファイルを列挙
2. 各ファイルを `bufio.Scanner` で行単位に読み取り
3. クエリをスペースで分割 → 全キーワードを含む行をマッチ（case-insensitive）
4. マッチ行の近くの H2/H3 ヘッダーをセクション名として抽出
5. ファイルごとにグルーピング → マッチ数で降順ソート
6. `maxResults` で結果数を制限

### 新アクションタイプ

```go
// pkg/schema/action.go に追加
ActionSearchKnowledge = "search_knowledge"
ActionReadKnowledge   = "read_knowledge"
```

```go
// Action 構造体に追加
KnowledgeQuery    string `json:"knowledge_query,omitempty"`    // search_knowledge 用
KnowledgePath     string `json:"knowledge_path,omitempty"`     // read_knowledge 用
```

### Loop への統合

```go
// internal/agent/loop.go の switch に追加
case schema.ActionSearchKnowledge:
    l.handleSearchKnowledge(action)

case schema.ActionReadKnowledge:
    l.handleReadKnowledge(action)
```

ハンドラは `l.lastToolOutput` に結果を格納。Brain の次のターンで利用される。

### Brain プロンプト

```
KNOWLEDGE ACTIONS:
- search_knowledge: Search pentesting knowledge base (HackTricks).
  Set knowledge_query to your search terms.
  Use this when you need to look up attack techniques, exploits, or methodologies.
- read_knowledge: Read a specific knowledge base article.
  Set knowledge_path to the file path from search results.
  Use this to get detailed information about a specific technique.
```

### 設定

```yaml
# config/knowledge.yaml
knowledge:
  - name: hacktricks
    path: "${HOME}/hacktricks/src"
```

パスの `${HOME}` は既存の `expandEnvString` で展開。

## 実装フェーズ

### Phase 1: Knowledge Store + テスト
- `internal/knowledge/store.go` — Store, Search, ReadFile, ListCategories
- `internal/knowledge/store_test.go` — テスト用の小さなマークダウンツリーで検証
- `internal/knowledge/config.go` — YAML 設定読み込み

### Phase 2: Schema + Loop 統合
- `pkg/schema/action.go` — 新アクション追加
- `internal/agent/loop.go` — ハンドラ追加
- `internal/brain/prompt.go` — プロンプト更新

### Phase 3: Main ワイヤリング
- `cmd/pentecter/main.go` — KnowledgeStore 生成 + Loop への注入
- ビルド + 手動テスト
