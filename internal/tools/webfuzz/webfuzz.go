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
//
// ワードリストはストリーミングで読み込み、1行ずつワーカーに送信する。
// これにより大きなワードリストでもメモリを大量消費せず、GC pause を抑制する。
func Run(ctx context.Context, opts Options, hitFn func(Hit), lineFn func(string)) error {
	// 1. ワードリストファイルを開く（fail fast: 存在しなければ即エラー）
	f, err := os.Open(opts.Wordlist)
	if err != nil {
		return fmt.Errorf("failed to load wordlist: %w", err)
	}

	// 2. HTTP クライアント生成
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

	// 3. Worker pool
	threads := opts.Threads
	if threads <= 0 {
		threads = 1
	}

	var sent atomic.Int64
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

	// 4. Producer goroutine: ファイルからストリーミング送信
	// ワードリスト全体を []string に読み込まず、1行ずつワーカーチャネルへ送信する。
	// これにより大量のヒープ割り当てと GC pressure を回避する。
	var scanErr error
	go func() {
		defer close(ch)
		defer func() { _ = f.Close() }()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			// ワード送信（ctx キャンセルで早期終了）
			if !sendWord(ctx, ch, line, &sent) {
				return
			}
			// dir モード: 拡張子付きバージョンもインライン送信
			if opts.Mode == "dir" {
				for _, ext := range opts.Extensions {
					if !sendWord(ctx, ch, line+ext, &sent) {
						return
					}
				}
			}
		}
		scanErr = scanner.Err()
	}()

	wg.Wait()

	// scanErr の読み取りは安全: close(ch) → workers drain → wg.Wait() 完了後
	if scanErr != nil {
		return fmt.Errorf("wordlist read error: %w", scanErr)
	}

	lineFn(fmt.Sprintf("[DONE] %d requests, %d hits", sent.Load(), hitCount.Load()))
	return nil
}

// sendWord はワードをチャネルに送信し、カウンターを増やす。
// ctx がキャンセルされた場合は false を返す。
func sendWord(ctx context.Context, ch chan<- string, word string, sent *atomic.Int64) bool {
	select {
	case <-ctx.Done():
		return false
	case ch <- word:
		sent.Add(1)
		return true
	}
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

	// Drain response body without buffering whole payload into memory.
	// This keeps connection reuse while reducing allocation/GC pressure.
	bodyBytes, err := io.Copy(io.Discard, resp.Body)
	if err != nil {
		return Hit{}, false, err
	}
	length := int(bodyBytes)

	hit := Hit{
		Input:      word,
		URL:        url,
		StatusCode: resp.StatusCode,
		Length:     length,
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
		MinVersion:         tls.VersionTLS12, // nosemgrep: go.lang.security.audit.crypto.missing-ssl-minversion.missing-ssl-minversion
	}
}
