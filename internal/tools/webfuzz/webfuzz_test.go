package webfuzz

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// writeWordlist はテスト用の一時ワードリストファイルを作成する。
func writeWordlist(t *testing.T, words []string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "wordlist-*.txt")
	if err != nil {
		t.Fatalf("failed to create temp wordlist: %v", err)
	}
	for _, w := range words {
		fmt.Fprintln(f, w)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("failed to close temp wordlist: %v", err)
	}
	return f.Name()
}

func TestRun_DirMode_BasicHits(t *testing.T) {
	// サーバー: /admin→200, /secret→403, それ以外→404
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin":
			w.WriteHeader(200)
			fmt.Fprint(w, "admin page")
		case "/secret":
			w.WriteHeader(403)
			fmt.Fprint(w, "forbidden")
		default:
			w.WriteHeader(404)
			fmt.Fprint(w, "not found")
		}
	}))
	defer ts.Close()

	wl := writeWordlist(t, []string{"admin", "secret", "notfound"})
	opts := Options{
		Mode:        "dir",
		URL:         ts.URL + "/FUZZ",
		Wordlist:    wl,
		Method:      "GET",
		Threads:     2,
		Timeout:     5 * time.Second,
		MatchStatus: append([]int{}, DefaultMatchStatus...),
	}

	var mu sync.Mutex
	var hits []Hit
	hitFn := func(h Hit) {
		mu.Lock()
		defer mu.Unlock()
		hits = append(hits, h)
	}
	var lines []string
	lineFn := func(s string) {
		mu.Lock()
		defer mu.Unlock()
		lines = append(lines, s)
	}

	err := Run(context.Background(), opts, hitFn, lineFn)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	// /admin (200) と /secret (403) はデフォルトマッチ対象
	// /notfound (404) はマッチ対象外
	if len(hits) != 2 {
		t.Errorf("got %d hits, want 2; hits: %+v", len(hits), hits)
	}

	foundAdmin := false
	foundSecret := false
	for _, h := range hits {
		if strings.HasSuffix(h.URL, "/admin") && h.StatusCode == 200 {
			foundAdmin = true
		}
		if strings.HasSuffix(h.URL, "/secret") && h.StatusCode == 403 {
			foundSecret = true
		}
	}
	if !foundAdmin {
		t.Error("expected hit for /admin, not found")
	}
	if !foundSecret {
		t.Error("expected hit for /secret, not found")
	}
}

func TestRun_DirMode_WithExtensions(t *testing.T) {
	// サーバー: /admin→200, /admin.php→200, それ以外→404
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin", "/admin.php":
			w.WriteHeader(200)
			fmt.Fprint(w, "ok")
		default:
			w.WriteHeader(404)
			fmt.Fprint(w, "not found")
		}
	}))
	defer ts.Close()

	wl := writeWordlist(t, []string{"admin"})
	opts := Options{
		Mode:        "dir",
		URL:         ts.URL + "/FUZZ",
		Wordlist:    wl,
		Method:      "GET",
		Threads:     2,
		Timeout:     5 * time.Second,
		Extensions:  []string{".php"},
		MatchStatus: []int{200},
	}

	var mu sync.Mutex
	var hits []Hit
	hitFn := func(h Hit) {
		mu.Lock()
		defer mu.Unlock()
		hits = append(hits, h)
	}
	lineFn := func(string) {}

	err := Run(context.Background(), opts, hitFn, lineFn)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	// "admin" → ["admin", "admin.php"] の2つがヒットする
	if len(hits) != 2 {
		t.Errorf("got %d hits, want 2; hits: %+v", len(hits), hits)
	}

	foundBase := false
	foundExt := false
	for _, h := range hits {
		if strings.HasSuffix(h.URL, "/admin") && !strings.HasSuffix(h.URL, "/admin.php") {
			foundBase = true
		}
		if strings.HasSuffix(h.URL, "/admin.php") {
			foundExt = true
		}
	}
	if !foundBase {
		t.Error("expected hit for /admin, not found")
	}
	if !foundExt {
		t.Error("expected hit for /admin.php, not found")
	}
}

func TestRun_FilterStatus(t *testing.T) {
	// サーバー: /admin→200, /secret→403
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin":
			w.WriteHeader(200)
			fmt.Fprint(w, "admin page")
		case "/secret":
			w.WriteHeader(403)
			fmt.Fprint(w, "forbidden")
		default:
			w.WriteHeader(404)
			fmt.Fprint(w, "not found")
		}
	}))
	defer ts.Close()

	wl := writeWordlist(t, []string{"admin", "secret"})
	opts := Options{
		Mode:         "dir",
		URL:          ts.URL + "/FUZZ",
		Wordlist:     wl,
		Method:       "GET",
		Threads:      2,
		Timeout:      5 * time.Second,
		MatchStatus:  append([]int{}, DefaultMatchStatus...),
		FilterStatus: []int{403}, // 403 をフィルタ
	}

	var mu sync.Mutex
	var hits []Hit
	hitFn := func(h Hit) {
		mu.Lock()
		defer mu.Unlock()
		hits = append(hits, h)
	}
	lineFn := func(string) {}

	err := Run(context.Background(), opts, hitFn, lineFn)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	// 403 はフィルタされるので /admin (200) のみヒット
	if len(hits) != 1 {
		t.Errorf("got %d hits, want 1; hits: %+v", len(hits), hits)
	}
	if len(hits) == 1 && hits[0].StatusCode != 200 {
		t.Errorf("expected status 200, got %d", hits[0].StatusCode)
	}
}

func TestRun_FilterSize(t *testing.T) {
	body := "exact body"
	bodyLen := len(body) // 10 bytes

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/small":
			w.WriteHeader(200)
			fmt.Fprint(w, body) // 10 bytes
		case "/big":
			w.WriteHeader(200)
			fmt.Fprint(w, "this is a much longer response body")
		default:
			w.WriteHeader(404)
		}
	}))
	defer ts.Close()

	wl := writeWordlist(t, []string{"small", "big"})
	opts := Options{
		Mode:        "dir",
		URL:         ts.URL + "/FUZZ",
		Wordlist:    wl,
		Method:      "GET",
		Threads:     2,
		Timeout:     5 * time.Second,
		MatchStatus: []int{200},
		FilterSize:  []int{bodyLen}, // 10 bytes をフィルタ
	}

	var mu sync.Mutex
	var hits []Hit
	hitFn := func(h Hit) {
		mu.Lock()
		defer mu.Unlock()
		hits = append(hits, h)
	}
	lineFn := func(string) {}

	err := Run(context.Background(), opts, hitFn, lineFn)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	// "small" (10 bytes) はフィルタされる、"big" のみヒット
	if len(hits) != 1 {
		t.Errorf("got %d hits, want 1; hits: %+v", len(hits), hits)
	}
	if len(hits) == 1 && !strings.HasSuffix(hits[0].URL, "/big") {
		t.Errorf("expected hit for /big, got %s", hits[0].URL)
	}
}

func TestRun_ContextCancel(t *testing.T) {
	// レスポンスに遅延を入れてキャンセルをテスト
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(200)
		fmt.Fprint(w, "ok")
	}))
	defer ts.Close()

	// 多くのワードを用意して、途中でキャンセル
	words := make([]string, 100)
	for i := range words {
		words[i] = fmt.Sprintf("word%d", i)
	}
	wl := writeWordlist(t, words)

	opts := Options{
		Mode:        "dir",
		URL:         ts.URL + "/FUZZ",
		Wordlist:    wl,
		Method:      "GET",
		Threads:     2,
		Timeout:     5 * time.Second,
		MatchStatus: []int{200},
	}

	ctx, cancel := context.WithCancel(context.Background())

	var mu sync.Mutex
	hitCount := 0
	hitFn := func(Hit) {
		mu.Lock()
		defer mu.Unlock()
		hitCount++
	}
	lineFn := func(string) {}

	// 少し待ってからキャンセル
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	err := Run(ctx, opts, hitFn, lineFn)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	// キャンセルにより全 100 件は処理されないはず
	mu.Lock()
	count := hitCount
	mu.Unlock()
	if count >= 100 {
		t.Errorf("expected fewer than 100 hits after cancel, got %d", count)
	}
}

func TestRun_ParamMode(t *testing.T) {
	// パラメーター名ファジング: ?FUZZ=value
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("id") != "" {
			w.WriteHeader(200)
			fmt.Fprint(w, "found param id")
			return
		}
		w.WriteHeader(404)
		fmt.Fprint(w, "not found")
	}))
	defer ts.Close()

	wl := writeWordlist(t, []string{"id", "name", "page"})
	opts := Options{
		Mode:        "param",
		URL:         ts.URL + "/search?FUZZ=test",
		Wordlist:    wl,
		Method:      "GET",
		Threads:     2,
		Timeout:     5 * time.Second,
		MatchStatus: []int{200},
	}

	var mu sync.Mutex
	var hits []Hit
	hitFn := func(h Hit) {
		mu.Lock()
		defer mu.Unlock()
		hits = append(hits, h)
	}
	lineFn := func(string) {}

	err := Run(context.Background(), opts, hitFn, lineFn)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	// id=test は 200 を返す
	if len(hits) != 1 {
		t.Errorf("got %d hits, want 1; hits: %+v", len(hits), hits)
	}
	if len(hits) == 1 && hits[0].Input != "id" {
		t.Errorf("expected hit input 'id', got %q", hits[0].Input)
	}
}

func TestRun_VhostMode(t *testing.T) {
	// vhost ファジング: Host ヘッダーに FUZZ を代入
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if strings.HasPrefix(host, "dev.") {
			w.WriteHeader(200)
			fmt.Fprint(w, "dev vhost found")
			return
		}
		w.WriteHeader(404)
		fmt.Fprint(w, "unknown vhost")
	}))
	defer ts.Close()

	wl := writeWordlist(t, []string{"dev", "staging", "api"})
	opts := Options{
		Mode:        "vhost",
		URL:         ts.URL + "/",
		Wordlist:    wl,
		Method:      "GET",
		Headers:     []string{"Host: FUZZ." + ts.Listener.Addr().String()},
		Threads:     2,
		Timeout:     5 * time.Second,
		MatchStatus: []int{200},
	}

	var mu sync.Mutex
	var hits []Hit
	hitFn := func(h Hit) {
		mu.Lock()
		defer mu.Unlock()
		hits = append(hits, h)
	}
	lineFn := func(string) {}

	err := Run(context.Background(), opts, hitFn, lineFn)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	// dev.host:port は 200、他は 404
	if len(hits) != 1 {
		t.Errorf("got %d hits, want 1; hits: %+v", len(hits), hits)
	}
	if len(hits) == 1 && hits[0].Input != "dev" {
		t.Errorf("expected hit input 'dev', got %q", hits[0].Input)
	}
}

func TestRun_PostMethod(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(405)
			fmt.Fprint(w, "method not allowed")
			return
		}
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(400)
			return
		}
		if r.PostFormValue("password") == "admin123" {
			w.WriteHeader(200)
			fmt.Fprint(w, "login success")
			return
		}
		w.WriteHeader(401)
		fmt.Fprint(w, "login failed")
	}))
	defer ts.Close()

	wl := writeWordlist(t, []string{"test", "admin123", "password"})
	opts := Options{
		Mode:        "param",
		URL:         ts.URL + "/login",
		Wordlist:    wl,
		Method:      "POST",
		Headers:     []string{"Content-Type: application/x-www-form-urlencoded"},
		Data:        "username=admin&password=FUZZ",
		Threads:     2,
		Timeout:     5 * time.Second,
		MatchStatus: []int{200},
	}

	var mu sync.Mutex
	var hits []Hit
	hitFn := func(h Hit) {
		mu.Lock()
		defer mu.Unlock()
		hits = append(hits, h)
	}
	lineFn := func(string) {}

	err := Run(context.Background(), opts, hitFn, lineFn)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if len(hits) != 1 {
		t.Errorf("got %d hits, want 1; hits: %+v", len(hits), hits)
	}
	if len(hits) == 1 && hits[0].Input != "admin123" {
		t.Errorf("expected hit input 'admin123', got %q", hits[0].Input)
	}
}

func TestRun_LineFnSummary(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, "ok")
	}))
	defer ts.Close()

	wl := writeWordlist(t, []string{"a", "b", "c"})
	opts := Options{
		Mode:        "dir",
		URL:         ts.URL + "/FUZZ",
		Wordlist:    wl,
		Method:      "GET",
		Threads:     2,
		Timeout:     5 * time.Second,
		MatchStatus: []int{200},
	}

	var mu sync.Mutex
	var lines []string
	hitFn := func(Hit) {}
	lineFn := func(s string) {
		mu.Lock()
		defer mu.Unlock()
		lines = append(lines, s)
	}

	err := Run(context.Background(), opts, hitFn, lineFn)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	// 最後の行が [DONE] サマリーであること
	mu.Lock()
	defer mu.Unlock()
	if len(lines) == 0 {
		t.Fatal("lineFn was never called")
	}
	last := lines[len(lines)-1]
	if !strings.HasPrefix(last, "[DONE]") {
		t.Errorf("last line = %q, want prefix [DONE]", last)
	}
	if !strings.Contains(last, "3 requests") {
		t.Errorf("last line = %q, want to contain '3 requests'", last)
	}
	if !strings.Contains(last, "3 hits") {
		t.Errorf("last line = %q, want to contain '3 hits'", last)
	}
}

func TestRun_EmptyWordlist(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer ts.Close()

	// 空のワードリスト（コメント行と空行のみ）
	wl := writeWordlist(t, []string{"# comment", "", "  "})
	opts := Options{
		Mode:        "dir",
		URL:         ts.URL + "/FUZZ",
		Wordlist:    wl,
		Method:      "GET",
		Threads:     2,
		Timeout:     5 * time.Second,
		MatchStatus: []int{200},
	}

	var mu sync.Mutex
	var hits []Hit
	var lines []string
	hitFn := func(h Hit) {
		mu.Lock()
		defer mu.Unlock()
		hits = append(hits, h)
	}
	lineFn := func(s string) {
		mu.Lock()
		defer mu.Unlock()
		lines = append(lines, s)
	}

	err := Run(context.Background(), opts, hitFn, lineFn)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if len(hits) != 0 {
		t.Errorf("got %d hits, want 0", len(hits))
	}

	// [DONE] 0 requests, 0 hits が出力されること
	mu.Lock()
	defer mu.Unlock()
	if len(lines) == 0 {
		t.Fatal("lineFn was never called")
	}
	last := lines[len(lines)-1]
	if !strings.Contains(last, "0 requests") {
		t.Errorf("last line = %q, want to contain '0 requests'", last)
	}
	if !strings.Contains(last, "0 hits") {
		t.Errorf("last line = %q, want to contain '0 hits'", last)
	}
}
