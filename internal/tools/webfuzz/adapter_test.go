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

	"github.com/0x6d61/pentecter/internal/tools"
)

// mockTreeUpdater は TreeUpdater のテスト用モック。
type mockTreeUpdater struct {
	mu         sync.Mutex
	endpoints  []endpointRecord
	vhosts     []vhostRecord
	completed  []completeRecord
	parameters []parameterRecord
	findings   []findingRecord
}

type parameterRecord struct {
	host, path, name, paramType string
	port                        int
}

type findingRecord struct {
	host, path, param, category, evidence, severity string
	port                                            int
}

type endpointRecord struct {
	host, parentPath, newPath string
	port, httpStatus          int
}

type vhostRecord struct {
	host, vhostName string
	port            int
}

type completeRecord struct {
	host, path string
	port       int
	taskType   int
}

func (m *mockTreeUpdater) AddEndpointWithStatus(host string, port int, parentPath, newPath string, httpStatus int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.endpoints = append(m.endpoints, endpointRecord{host: host, port: port, parentPath: parentPath, newPath: newPath, httpStatus: httpStatus})
}

func (m *mockTreeUpdater) AddVhost(parentHost string, port int, vhostName string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.vhosts = append(m.vhosts, vhostRecord{host: parentHost, port: port, vhostName: vhostName})
}

func (m *mockTreeUpdater) CompleteTask(host string, port int, path string, taskType int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.completed = append(m.completed, completeRecord{host: host, port: port, path: path, taskType: taskType})
}

func (m *mockTreeUpdater) AddParameter(host string, port int, path string, name string, paramType string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.parameters = append(m.parameters, parameterRecord{host: host, port: port, path: path, name: name, paramType: paramType})
}

func (m *mockTreeUpdater) AddFinding(host string, port int, path string, param, category, evidence, severity string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.findings = append(m.findings, findingRecord{host: host, port: port, path: path, param: param, category: category, evidence: evidence, severity: severity})
}

func TestWebfuzzTool_Execute_DirMode(t *testing.T) {
	// テストサーバー
	mux := http.NewServeMux()
	mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, "admin page")
	})
	mux.HandleFunc("/secret", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		fmt.Fprint(w, "forbidden")
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		fmt.Fprint(w, "not found")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// ワードリスト
	wordlist := createTempWordlist(t, "admin\nsecret\nnotfound\n")

	tree := &mockTreeUpdater{}
	tool := NewWebfuzzTool(tree, "10.0.0.1")

	lineCh := make(chan tools.OutputLine, 256)
	var lines []string
	done := make(chan struct{})
	go func() {
		for line := range lineCh {
			lines = append(lines, line.Content)
		}
		close(done)
	}()

	exitCode, err := tool.Execute(context.Background(),
		[]string{"dir", "-u", srv.URL + "/FUZZ", "-w", wordlist, "-t", "1"},
		lineCh)
	close(lineCh)
	<-done

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	// エンドポイントが追加されたことを確認
	tree.mu.Lock()
	defer tree.mu.Unlock()
	if len(tree.endpoints) < 2 {
		t.Fatalf("expected at least 2 endpoints, got %d", len(tree.endpoints))
	}

	// HIT 行と DONE 行が出力されたことを確認
	var hasHit, hasDone bool
	for _, line := range lines {
		if strings.Contains(line, "[HIT]") {
			hasHit = true
		}
		if strings.Contains(line, "[DONE]") {
			hasDone = true
		}
	}
	if !hasHit {
		t.Error("expected [HIT] line in output")
	}
	if !hasDone {
		t.Error("expected [DONE] line in output")
	}
}

func TestWebfuzzTool_Execute_VhostMode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host == "dev.example.com" {
			w.WriteHeader(200)
			fmt.Fprint(w, "dev site")
			return
		}
		w.WriteHeader(200)
		// デフォルトレスポンス（フィルタサイズ用）
		fmt.Fprint(w, "default")
	}))
	defer srv.Close()

	wordlist := createTempWordlist(t, "dev\nstaging\n")

	tree := &mockTreeUpdater{}
	tool := NewWebfuzzTool(tree, "10.0.0.1")

	lineCh := make(chan tools.OutputLine, 256)
	go func() {
		for range lineCh {
		}
	}()

	// デフォルトレスポンスサイズ (7 bytes = "default") をフィルタ
	exitCode, err := tool.Execute(context.Background(),
		[]string{"vhost", "-u", srv.URL, "-w", wordlist, "-H", "Host: FUZZ.example.com", "-fs", "7", "-t", "1"},
		lineCh)
	close(lineCh)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	// dev.example.com が vhost として追加されたことを確認
	tree.mu.Lock()
	defer tree.mu.Unlock()
	if len(tree.vhosts) != 1 {
		t.Fatalf("expected 1 vhost, got %d", len(tree.vhosts))
	}
	if tree.vhosts[0].vhostName != "dev.example.com" {
		t.Errorf("expected vhost dev.example.com, got %s", tree.vhosts[0].vhostName)
	}
}

func TestWebfuzzTool_Execute_InvalidArgs(t *testing.T) {
	tool := NewWebfuzzTool(nil, "10.0.0.1")
	lineCh := make(chan tools.OutputLine, 256)
	go func() {
		for range lineCh {
		}
	}()

	exitCode, err := tool.Execute(context.Background(), []string{"invalid"}, lineCh)
	close(lineCh)

	if err == nil {
		t.Fatal("expected error for invalid subcommand")
	}
	if exitCode != 1 {
		t.Fatalf("expected exit code 1, got %d", exitCode)
	}
}

func TestWebfuzzTool_Execute_NilTree(t *testing.T) {
	// tree が nil でもエラーなく動作すること
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	wordlist := createTempWordlist(t, "test\n")

	tool := NewWebfuzzTool(nil, "10.0.0.1")
	lineCh := make(chan tools.OutputLine, 256)
	go func() {
		for range lineCh {
		}
	}()

	exitCode, err := tool.Execute(context.Background(),
		[]string{"dir", "-u", srv.URL + "/FUZZ", "-w", wordlist, "-t", "1"},
		lineCh)
	close(lineCh)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}
}

func TestExtractPortAndPath(t *testing.T) {
	tests := []struct {
		url      string
		wantPort int
		wantPath string
	}{
		{"http://example.com/FUZZ", 80, "/"},
		{"https://example.com/FUZZ", 443, "/"},
		{"http://example.com:8080/FUZZ", 8080, "/"},
		{"http://example.com/admin/FUZZ", 80, "/admin"},
		{"http://example.com/page?FUZZ=value", 80, "/page"},
		{"http://example.com//FUZZ", 80, "/"},
		{"http://example.com///api//FUZZ", 80, "/api"},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			port, path := extractPortAndPath(tt.url)
			if port != tt.wantPort {
				t.Errorf("port: got %d, want %d", port, tt.wantPort)
			}
			if path != tt.wantPath {
				t.Errorf("path: got %q, want %q", path, tt.wantPath)
			}
		})
	}
}

func TestNormalizeTreePath(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"", "/"},
		{"/", "/"},
		{"//", "/"},
		{"admin", "/admin"},
		{"/admin/", "/admin"},
		{"//admin//login/", "/admin/login"},
		{"  /api/v1  ", "/api/v1"},
	}

	for _, tt := range tests {
		got := normalizeTreePath(tt.in)
		if got != tt.want {
			t.Errorf("normalizeTreePath(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestExtractDomainFromHeaders(t *testing.T) {
	tests := []struct {
		headers []string
		want    string
	}{
		{[]string{"Host: FUZZ.example.com"}, "example.com"},
		{[]string{"Content-Type: text/html", "Host: FUZZ.test.local"}, "test.local"},
		{[]string{"Content-Type: text/html"}, "unknown"},
	}

	for _, tt := range tests {
		got := extractDomainFromHeaders(tt.headers)
		if got != tt.want {
			t.Errorf("extractDomainFromHeaders(%v) = %q, want %q", tt.headers, got, tt.want)
		}
	}
}

func TestWebfuzzTool_Execute_ContextCancel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(200)
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	// 100ワードのワードリスト
	var words []string
	for i := 0; i < 100; i++ {
		words = append(words, fmt.Sprintf("word%d", i))
	}
	wordlist := createTempWordlist(t, strings.Join(words, "\n"))

	tool := NewWebfuzzTool(nil, "10.0.0.1")
	lineCh := make(chan tools.OutputLine, 256)
	go func() {
		for range lineCh {
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	_, _ = tool.Execute(ctx, []string{"dir", "-u", srv.URL + "/FUZZ", "-w", wordlist, "-t", "2"}, lineCh)
	close(lineCh)
	// キャンセルされたことだけ確認（エラーは出ない設計）
}

func TestExtractPathFromHitURL(t *testing.T) {
	tests := []struct {
		name       string
		hitURL     string
		parentPath string
		input      string
		want       string
	}{
		{"valid URL", "http://example.com/admin", "/", "admin", "/admin"},
		{"valid URL with subpath", "http://example.com/api/v1", "/api", "v1", "/api/v1"},
		{"invalid URL fallback", "://invalid", "/api", "users", "/api/users"},
		{"empty URL fallback", "", "/", "test", "/test"},
		{"fallback without leading slash", "://bad", "dir", "file", "/dir/file"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractPathFromHitURL(tt.hitURL, tt.parentPath, tt.input)
			if got != tt.want {
				t.Errorf("extractPathFromHitURL(%q, %q, %q) = %q, want %q",
					tt.hitURL, tt.parentPath, tt.input, got, tt.want)
			}
		})
	}
}

func TestExtractDomainFromHeaders_QuotedEnd(t *testing.T) {
	// クォートで終端するケース
	tests := []struct {
		headers []string
		want    string
	}{
		{[]string{`Host: FUZZ.example.com"`}, "example.com"},
		{[]string{"Host: FUZZ.test.local'"}, "test.local"},
		{[]string{"Host: FUZZ.space.end  extra"}, "space.end"},
	}
	for _, tt := range tests {
		got := extractDomainFromHeaders(tt.headers)
		if got != tt.want {
			t.Errorf("extractDomainFromHeaders(%v) = %q, want %q", tt.headers, got, tt.want)
		}
	}
}

func TestWebfuzzTool_Execute_ParamMode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("id") != "" {
			w.WriteHeader(200)
			fmt.Fprint(w, "found")
			return
		}
		w.WriteHeader(404)
		fmt.Fprint(w, "not found")
	}))
	defer srv.Close()

	wordlist := createTempWordlist(t, "id\nname\n")

	tree := &mockTreeUpdater{}
	tool := NewWebfuzzTool(tree, "10.0.0.1")

	lineCh := make(chan tools.OutputLine, 256)
	go func() {
		for range lineCh {
		}
	}()

	exitCode, err := tool.Execute(context.Background(),
		[]string{"param", "-u", srv.URL + "/page?FUZZ=test", "-w", wordlist, "-mc", "200", "-t", "1"},
		lineCh)
	close(lineCh)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	// param モードでは CompleteTask が呼ばれる
	tree.mu.Lock()
	defer tree.mu.Unlock()
	if len(tree.completed) == 0 {
		t.Error("expected CompleteTask to be called for param mode")
	}
}

func TestWebfuzzTool_Execute_VhostMode_CompletesTask(t *testing.T) {
	// Bug 2: vhost モードで列挙完了後に CompleteTask(taskType=4=TaskVhostDiscov) が呼ばれることを確認
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, "default")
	}))
	defer srv.Close()

	wordlist := createTempWordlist(t, "dev\n")

	tree := &mockTreeUpdater{}
	tool := NewWebfuzzTool(tree, "10.0.0.1")

	lineCh := make(chan tools.OutputLine, 256)
	go func() {
		for range lineCh {
		}
	}()

	exitCode, err := tool.Execute(context.Background(),
		[]string{"vhost", "-u", srv.URL, "-w", wordlist, "-H", "Host: FUZZ.example.com", "-fs", "99999", "-t", "1"},
		lineCh)
	close(lineCh)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	// vhost モード完了で CompleteTask(taskType=4=TaskVhostDiscov) が呼ばれるべき
	tree.mu.Lock()
	defer tree.mu.Unlock()
	found := false
	for _, c := range tree.completed {
		if c.taskType == 4 { // TaskVhostDiscov
			found = true
		}
	}
	if !found {
		t.Error("expected CompleteTask(taskType=4=TaskVhostDiscov) for vhost mode completion")
	}
}

func TestWebfuzzTool_Execute_ParamMode_NoHits_CompletesTask(t *testing.T) {
	// Bug 2 (related): param モードでヒットが0件でも CompleteTask が呼ばれることを確認
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		fmt.Fprint(w, "not found")
	}))
	defer srv.Close()

	wordlist := createTempWordlist(t, "id\nname\n")

	tree := &mockTreeUpdater{}
	tool := NewWebfuzzTool(tree, "10.0.0.1")

	lineCh := make(chan tools.OutputLine, 256)
	go func() {
		for range lineCh {
		}
	}()

	exitCode, err := tool.Execute(context.Background(),
		[]string{"param", "-u", srv.URL + "/page?FUZZ=test", "-w", wordlist, "-mc", "200", "-t", "1"},
		lineCh)
	close(lineCh)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	// ヒット0件でも CompleteTask(taskType=1=TaskParamFuzz) が呼ばれるべき
	tree.mu.Lock()
	defer tree.mu.Unlock()
	found := false
	for _, c := range tree.completed {
		if c.taskType == 1 { // TaskParamFuzz
			found = true
		}
	}
	if !found {
		t.Error("expected CompleteTask(taskType=1=TaskParamFuzz) for param mode completion even with 0 hits")
	}
}

func TestWebfuzzTool_Execute_DirMode_CompletesTask(t *testing.T) {
	// dir モードで列挙完了後に CompleteTask(taskType=0) が呼ばれることを確認
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		fmt.Fprint(w, "not found")
	}))
	defer srv.Close()

	wordlist := createTempWordlist(t, "nothing\n")

	tree := &mockTreeUpdater{}
	tool := NewWebfuzzTool(tree, "10.0.0.1")

	lineCh := make(chan tools.OutputLine, 256)
	go func() {
		for range lineCh {
		}
	}()

	exitCode, err := tool.Execute(context.Background(),
		[]string{"dir", "-u", srv.URL + "/FUZZ", "-w", wordlist, "-t", "1"},
		lineCh)
	close(lineCh)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	// dir モード完了で CompleteTask(taskType=0=TaskEndpointEnum) が呼ばれる
	tree.mu.Lock()
	defer tree.mu.Unlock()
	found := false
	for _, c := range tree.completed {
		if c.taskType == 0 {
			found = true
		}
	}
	if !found {
		t.Error("expected CompleteTask(taskType=0) for dir mode completion")
	}
}

func TestWebfuzzTool_Execute_DirMode_DoubleSlashURL_ParentNormalized(t *testing.T) {
	// URL が //FUZZ でも parentPath が "/" として処理されることを確認
	mux := http.NewServeMux()
	mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, "admin")
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		fmt.Fprint(w, "not found")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	wordlist := createTempWordlist(t, "admin\n")
	tree := &mockTreeUpdater{}
	tool := NewWebfuzzTool(tree, "10.0.0.1")

	lineCh := make(chan tools.OutputLine, 64)
	go func() {
		for range lineCh {
		}
	}()

	exitCode, err := tool.Execute(context.Background(),
		[]string{"dir", "-u", srv.URL + "//FUZZ", "-w", wordlist, "-t", "1"},
		lineCh)
	close(lineCh)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	tree.mu.Lock()
	defer tree.mu.Unlock()
	if len(tree.endpoints) == 0 {
		t.Fatal("expected endpoint to be recorded")
	}
	got := tree.endpoints[0]
	if got.parentPath != "/" {
		t.Fatalf("parentPath = %q, want /", got.parentPath)
	}
	if got.newPath != "/admin" {
		t.Fatalf("newPath = %q, want /admin", got.newPath)
	}
}

func TestWebfuzzTool_Execute_DirMode_TrailingSlashWord_ParentNormalized(t *testing.T) {
	// ワードリストに "admin/" があっても parentPath は "/"、newPath は "/admin" になること
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, "admin slash")
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		fmt.Fprint(w, "not found")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	wordlist := createTempWordlist(t, "admin/\n")
	tree := &mockTreeUpdater{}
	tool := NewWebfuzzTool(tree, "10.0.0.1")

	lineCh := make(chan tools.OutputLine, 64)
	go func() {
		for range lineCh {
		}
	}()

	exitCode, err := tool.Execute(context.Background(),
		[]string{"dir", "-u", srv.URL + "/FUZZ", "-w", wordlist, "-t", "1"},
		lineCh)
	close(lineCh)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	tree.mu.Lock()
	defer tree.mu.Unlock()
	if len(tree.endpoints) == 0 {
		t.Fatal("expected endpoint to be recorded")
	}
	got := tree.endpoints[0]
	if got.parentPath != "/" {
		t.Fatalf("parentPath = %q, want /", got.parentPath)
	}
	if got.newPath != "/admin" {
		t.Fatalf("newPath = %q, want /admin", got.newPath)
	}
}

func createTempWordlist(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "wordlist-*.txt")
	if err != nil {
		t.Fatalf("failed to create temp wordlist: %v", err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("failed to write wordlist: %v", err)
	}
	f.Close()
	return f.Name()
}
