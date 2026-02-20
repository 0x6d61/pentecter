// Package knowledge はペンテスト知識ベース（HackTricks 等）への
// 検索・読み取り機能を提供する。
package knowledge

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Store はナレッジベースへの検索・読み取りインターフェース
type Store struct {
	basePath string // clone 済みリポジトリの src/ ディレクトリ
}

// SearchResult は検索結果1件を表す
type SearchResult struct {
	File       string // 相対パス（例: "pentesting-web/sql-injection/README.md"）
	Title      string // 最初の H1 ヘッダー
	Section    string // マッチしたセクションの H2/H3 ヘッダー
	Snippet    string // マッチ行の前後コンテキスト（3行程度）
	MatchCount int    // マッチ数
}

// Category はナレッジベースのカテゴリ
type Category struct {
	Name      string // ディレクトリ名
	Path      string // 相対パス
	FileCount int    // 配下のマークダウンファイル数
}

// NewStore はナレッジベースのパスを受け取り Store を作成する。
// パスが空または存在しない場合は nil を返す（graceful skip）。
func NewStore(basePath string) *Store {
	if basePath == "" {
		return nil
	}
	info, err := os.Stat(basePath)
	if err != nil || !info.IsDir() {
		return nil
	}
	return &Store{basePath: basePath}
}

// Search はクエリに一致するファイル・セクションを返す。
// - クエリをスペースで分割 → 全キーワードがファイル内のどこかに存在すればマッチ（file-level AND, case-insensitive）
// - スニペットは最初にキーワードが出現した行の前後コンテキスト
// - マッチ行の近くの H2/H3 ヘッダーをセクション名として抽出
// - ファイルごとにグルーピング → マッチ数で降順ソート
// - maxResults で結果数を制限
func (s *Store) Search(query string, maxResults int) []SearchResult {
	query = strings.TrimSpace(query)
	if query == "" {
		return nil
	}

	// クエリをスペースで分割し、小文字に変換
	keywords := strings.Fields(strings.ToLower(query))
	if len(keywords) == 0 {
		return nil
	}

	// ファイルごとの検索結果を格納する map
	type fileMatch struct {
		relPath    string
		title      string   // 最初の H1 ヘッダー
		section    string   // 最後にマッチしたセクション
		lines      []string // ファイルの全行（スニペット用）
		matchLines []int    // マッチした行番号
		matchCount int
	}

	var results []fileMatch

	// basePath 以下の全 .md ファイルを走査
	_ = filepath.WalkDir(s.basePath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // エラーのあるディレクトリはスキップ
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(d.Name()), ".md") {
			return nil
		}

		// ファイルを読み込み
		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer func() { _ = f.Close() }()

		relPath, err := filepath.Rel(s.basePath, path)
		if err != nil {
			return nil
		}
		// Windows パス区切り文字をスラッシュに変換
		relPath = filepath.ToSlash(relPath)

		var (
			lines          []string
			title          string
			currentSection string
			matchSection   string
			firstMatchLine = -1
			matchCount     int
		)

		// キーワードごとのファイル内出現フラグ
		keywordFound := make([]bool, len(keywords))

		scanner := bufio.NewScanner(f)
		lineNum := 0
		for scanner.Scan() {
			line := scanner.Text()
			lines = append(lines, line)

			// H1 ヘッダーを抽出（最初の1つだけ）
			if title == "" && strings.HasPrefix(line, "# ") && !strings.HasPrefix(line, "## ") {
				title = strings.TrimPrefix(line, "# ")
				title = strings.TrimSpace(title)
			}

			// H2/H3 ヘッダーを追跡
			if strings.HasPrefix(line, "## ") || strings.HasPrefix(line, "### ") {
				trimmed := strings.TrimLeft(line, "#")
				currentSection = strings.TrimSpace(trimmed)
			}

			// 各キーワードの出現をチェック（file-level AND）
			lowerLine := strings.ToLower(line)
			lineHasMatch := false
			for ki, kw := range keywords {
				if strings.Contains(lowerLine, kw) {
					keywordFound[ki] = true
					matchCount++
					lineHasMatch = true
				}
			}

			// 最初のマッチ行を記録（スニペット用）
			if lineHasMatch && firstMatchLine < 0 {
				firstMatchLine = lineNum
				if currentSection != "" {
					matchSection = currentSection
				}
			}

			lineNum++
		}

		// 全キーワードがファイル内に存在する場合のみマッチ
		allFound := true
		for _, found := range keywordFound {
			if !found {
				allFound = false
				break
			}
		}

		if allFound && matchCount > 0 {
			matchLines := []int{}
			if firstMatchLine >= 0 {
				matchLines = append(matchLines, firstMatchLine)
			}
			results = append(results, fileMatch{
				relPath:    relPath,
				title:      title,
				section:    matchSection,
				lines:      lines,
				matchLines: matchLines,
				matchCount: matchCount,
			})
		}

		return nil
	})

	// マッチ数で降順ソート
	sort.Slice(results, func(i, j int) bool {
		return results[i].matchCount > results[j].matchCount
	})

	// maxResults で制限
	if maxResults > 0 && len(results) > maxResults {
		results = results[:maxResults]
	}

	// SearchResult に変換
	searchResults := make([]SearchResult, len(results))
	for i, fm := range results {
		snippet := buildSnippet(fm.lines, fm.matchLines, 3)
		searchResults[i] = SearchResult{
			File:       fm.relPath,
			Title:      fm.title,
			Section:    fm.section,
			Snippet:    snippet,
			MatchCount: fm.matchCount,
		}
	}

	return searchResults
}

// buildSnippet はマッチ行の前後 contextLines 行をスニペットとして結合する。
// 最初のマッチ行のコンテキストのみ返す。
func buildSnippet(lines []string, matchLines []int, contextLines int) string {
	if len(matchLines) == 0 || len(lines) == 0 {
		return ""
	}

	// 最初のマッチ行を使用
	matchLine := matchLines[0]
	start := matchLine - contextLines
	if start < 0 {
		start = 0
	}
	end := matchLine + contextLines + 1
	if end > len(lines) {
		end = len(lines)
	}

	var sb strings.Builder
	for i := start; i < end; i++ {
		if sb.Len() > 0 {
			sb.WriteString("\n")
		}
		sb.WriteString(lines[i])
	}
	return sb.String()
}

// ReadFile は指定パスのマークダウンファイルを読む。
// パスは basePath からの相対パス。maxBytes でサイズ上限を設ける。
// パストラバーサル攻撃を防ぐため、basePath 外へのアクセスを拒否する。
func (s *Store) ReadFile(path string, maxBytes int) (string, error) {
	// パスをクリーンアップ
	cleanPath := filepath.Clean(filepath.FromSlash(path))

	// 絶対パスを構築
	absPath := filepath.Join(s.basePath, cleanPath)

	// パストラバーサル検証: 解決されたパスが basePath 内にあることを確認
	absResolved, err := filepath.Abs(absPath)
	if err != nil {
		return "", fmt.Errorf("knowledge: failed to resolve path: %w", err)
	}
	baseResolved, err := filepath.Abs(s.basePath)
	if err != nil {
		return "", fmt.Errorf("knowledge: failed to resolve base path: %w", err)
	}

	// basePath 外へのアクセスを拒否
	rel, err := filepath.Rel(baseResolved, absResolved)
	if err != nil {
		return "", fmt.Errorf("knowledge: path traversal detected")
	}
	if strings.HasPrefix(rel, "..") {
		return "", fmt.Errorf("knowledge: path traversal detected: path escapes base directory")
	}

	// ファイル読み込み
	data, err := os.ReadFile(absResolved)
	if err != nil {
		return "", fmt.Errorf("knowledge: failed to read file %s: %w", path, err)
	}

	// maxBytes で切り詰め
	if maxBytes > 0 && len(data) > maxBytes {
		data = data[:maxBytes]
	}

	return string(data), nil
}

// ListCategories はトップレベルカテゴリ一覧を返す。
// トップレベルディレクトリをカテゴリとして扱い、配下の .md ファイル数をカウントする。
func (s *Store) ListCategories() []Category {
	entries, err := os.ReadDir(s.basePath)
	if err != nil {
		return nil
	}

	var categories []Category
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		name := entry.Name()
		// 隠しディレクトリをスキップ
		if strings.HasPrefix(name, ".") {
			continue
		}

		// 配下の .md ファイル数をカウント
		fileCount := countMarkdownFiles(filepath.Join(s.basePath, name))

		categories = append(categories, Category{
			Name:      name,
			Path:      name,
			FileCount: fileCount,
		})
	}

	// 名前でソート（安定した出力のため）
	sort.Slice(categories, func(i, j int) bool {
		return categories[i].Name < categories[j].Name
	})

	return categories
}

// countMarkdownFiles はディレクトリ配下の .md ファイル数を再帰的にカウントする。
func countMarkdownFiles(dir string) int {
	count := 0
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !d.IsDir() && strings.HasSuffix(strings.ToLower(d.Name()), ".md") {
			count++
		}
		return nil
	})
	return count
}
