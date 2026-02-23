package webfuzz

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
)

// Hit はファジングで発見された1件のヒット。
type Hit struct {
	Input      string // FUZZ に代入された値
	URL        string // 完全 URL
	StatusCode int
	Length     int // レスポンスボディのバイト数
	Words      int // レスポンスボディの単語数
	Lines      int // レスポンスボディの行数
}

// Run はファジングを実行する。
// ワードリストの各エントリについて HTTP リクエストを送り、マッチ条件に合致したらヒットとして通知する。
// hitFn: ヒットごとに呼ばれるコールバック（AttackDataTree 更新用）
// lineFn: TUI 表示用のサマリー行コールバック（例: "[HIT] /admin [301] [1234B]"）
func Run(ctx context.Context, opts Options, hitFn func(Hit), lineFn func(string)) error {
	// 1. ワードリスト読み込み
	words, err := loadWordlist(opts.Wordlist)
	if err != nil {
		return fmt.Errorf("failed to load wordlist: %w", err)
	}

	// 2. extensions 展開（dir モードのみ）
	words = expandExtensions(words, opts.Mode, opts.Extensions)

	total := len(words)
	if total == 0 {
		lineFn("[DONE] 0 requests, 0 hits")
		return nil
	}

	// 3. HTTP クライアント生成
	client := &http.Client{
		Timeout: opts.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: pentestTLSConfig(),
		},
		// リダイレクトを追跡しない（ステータスコードをそのまま取得するため）
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// 4. Worker pool
	threads := opts.Threads
	if threads <= 0 {
		threads = 1
	}
	if threads > total {
		threads = total
	}

	var hitCount atomic.Int64
	var wg sync.WaitGroup
	ch := make(chan string, threads)

	// ワーカー起動
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for word := range ch {
				select {
				case <-ctx.Done():
					return
				default:
				}

				hit, ok, fuzzErr := fuzzOne(ctx, client, opts, word)
				if fuzzErr != nil {
					// ネットワークエラーなどは無視して続行
					continue
				}
				if ok {
					hitCount.Add(1)
					hitFn(hit)
					lineFn(fmt.Sprintf("[HIT] %s [%d] [%dB]", hit.URL, hit.StatusCode, hit.Length))
				}
			}
		}()
	}

	// ワードをチャネルに送信
	for _, word := range words {
		if ctx.Err() != nil {
			break
		}
		select {
		case <-ctx.Done():
		case ch <- word:
		}
	}
	close(ch)
	wg.Wait()

	lineFn(fmt.Sprintf("[DONE] %d requests, %d hits", total, hitCount.Load()))
	return nil
}

// loadWordlist はワードリストファイルを読み込み、空行とコメント行をスキップして返す。
func loadWordlist(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var words []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		words = append(words, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return words, nil
}

// expandExtensions は dir モードの場合、各ワードに拡張子付きバージョンを追加する。
func expandExtensions(words []string, mode string, extensions []string) []string {
	if mode != "dir" || len(extensions) == 0 {
		return words
	}

	expanded := make([]string, 0, len(words)*(1+len(extensions)))
	for _, w := range words {
		expanded = append(expanded, w)
		for _, ext := range extensions {
			expanded = append(expanded, w+ext)
		}
	}
	return expanded
}

// fuzzOne は1つのワードに対してリクエストを送り、マッチ判定を行う。
// マッチした場合は (Hit, true, nil) を返す。
func fuzzOne(ctx context.Context, client *http.Client, opts Options, word string) (Hit, bool, error) {
	// URL 構築
	url := strings.ReplaceAll(opts.URL, "FUZZ", word)

	// リクエスト生成
	method := opts.Method
	var bodyReader io.Reader
	if opts.Data != "" {
		data := strings.ReplaceAll(opts.Data, "FUZZ", word)
		bodyReader = strings.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return Hit{}, false, err
	}

	// ヘッダー設定
	for _, h := range opts.Headers {
		headerVal := strings.ReplaceAll(h, "FUZZ", word)
		parts := strings.SplitN(headerVal, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			// Go の HTTP クライアントは Host ヘッダーを req.Header からは送信しない。
			// req.Host に設定する必要がある。
			if strings.EqualFold(key, "Host") {
				req.Host = val
			} else {
				req.Header.Set(key, val)
			}
		}
	}

	// リクエスト送信
	resp, err := client.Do(req)
	if err != nil {
		return Hit{}, false, err
	}
	defer func() { _ = resp.Body.Close() }()

	// レスポンスボディ読み取り
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return Hit{}, false, err
	}

	bodyStr := string(body)
	length := len(body)
	wordCount := countWords(bodyStr)
	lineCount := countLines(bodyStr)

	hit := Hit{
		Input:      word,
		URL:        url,
		StatusCode: resp.StatusCode,
		Length:     length,
		Words:      wordCount,
		Lines:      lineCount,
	}

	// マッチ/フィルタ判定
	if !shouldReport(hit, opts) {
		return Hit{}, false, nil
	}

	return hit, true, nil
}

// shouldReport はヒットを報告すべきかどうかを判定する。
// FilterStatus/FilterSize が優先（マッチしていてもフィルタで除外される）。
func shouldReport(hit Hit, opts Options) bool {
	// FilterStatus チェック（優先）
	if len(opts.FilterStatus) > 0 && containsInt(opts.FilterStatus, hit.StatusCode) {
		return false
	}

	// FilterSize チェック（優先）
	if len(opts.FilterSize) > 0 && containsInt(opts.FilterSize, hit.Length) {
		return false
	}

	// MatchStatus チェック
	if len(opts.MatchStatus) > 0 {
		return containsInt(opts.MatchStatus, hit.StatusCode)
	}

	// MatchStatus が空なら全てマッチ
	return true
}

// containsInt はスライスに値が含まれるかチェックする。
func containsInt(slice []int, val int) bool {
	for _, v := range slice {
		if v == val {
			return true
		}
	}
	return false
}

// countWords はテキスト内の単語数をカウントする。
func countWords(s string) int {
	return len(strings.Fields(s))
}

// countLines はテキスト内の行数をカウントする。
func countLines(s string) int {
	if s == "" {
		return 0
	}
	n := strings.Count(s, "\n")
	// 末尾に改行がなければ +1
	if !strings.HasSuffix(s, "\n") {
		n++
	}
	return n
}

// pentestTLSConfig はペンテスト用の TLS 設定を返す。
// 自己署名証明書のターゲットに接続するため InsecureSkipVerify を有効にしている。
// これはペネトレーションテストツール専用の意図的な設定である。
func pentestTLSConfig() *tls.Config {
	// nosemgrep: problem-based-packs.insecure-transport.go-stdlib.bypass-tls-verification.bypass-tls-verification
	return &tls.Config{
		InsecureSkipVerify: true,             // #nosec G402 -- pentest tool: must connect to targets with self-signed certs
		MinVersion:         tls.VersionTLS13, // nosemgrep: go.lang.security.audit.crypto.missing-ssl-minversion.missing-ssl-minversion
	}
}
