package mcp

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// mockServerPair はテスト用のモックサーバーと対応するクライアントのペア
type mockServerPair struct {
	mock   *mockMCPServer
	client *MCPClient
}

// newTestManager はテスト用の MCPManager をモッククライアント付きで作成する。
// 各サーバー設定に対してモック MCP サーバーを起動し、マネージャーに注入する。
func newTestManager(t *testing.T, configs []ServerConfig) (*MCPManager, []*mockServerPair) {
	t.Helper()

	pairs := make([]*mockServerPair, len(configs))
	clients := make(map[string]*MCPClient, len(configs))

	for i, cfg := range configs {
		mock, client := newMockMCPServer(t)
		pairs[i] = &mockServerPair{mock: mock, client: client}
		clients[cfg.Name] = client
	}

	m := &MCPManager{
		clients: clients,
		configs: configs,
		tools:   make(map[string][]ToolSchema),
	}

	return m, pairs
}

func TestManager_NewManager_NoConfigFile(t *testing.T) {
	// 設定ファイルが存在しない場合は nil, nil を返す
	m, err := NewManager("/nonexistent/path/mcp.yaml")
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if m != nil {
		t.Fatal("expected nil manager for missing config file")
	}
}

func TestManager_NewManager_EmptyServers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp.yaml")
	if err := os.WriteFile(path, []byte("servers: []\n"), 0644); err != nil {
		t.Fatal(err)
	}

	m, err := NewManager(path)
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if m == nil {
		t.Fatal("expected non-nil manager")
	}
	if len(m.ListAllTools()) != 0 {
		t.Error("expected no tools for empty servers config")
	}
}

func TestManager_NewManager_ValidConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp.yaml")
	content := `servers:
  - name: test-server
    command: echo
    args: ["hello"]
    proposal_required: true
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	m, err := NewManager(path)
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if m == nil {
		t.Fatal("expected non-nil manager")
	}
	if len(m.configs) != 1 {
		t.Fatalf("expected 1 config, got %d", len(m.configs))
	}
	if m.configs[0].Name != "test-server" {
		t.Errorf("expected server name 'test-server', got '%s'", m.configs[0].Name)
	}
}

func TestManager_ListAllTools_Aggregation(t *testing.T) {
	// 複数サーバーのツールが集約されること
	configs := []ServerConfig{
		{Name: "server-a", Command: "echo"},
		{Name: "server-b", Command: "echo"},
	}
	mgr, pairs := newTestManager(t, configs)
	defer func() {
		for _, p := range pairs {
			p.mock.close()
			p.client.Close()
		}
	}()

	// 手動でツールを登録（StartAll をスキップして直接テスト）
	mgr.tools["server-a"] = []ToolSchema{
		{Server: "server-a", Name: "tool_a1", Description: "Tool A1"},
		{Server: "server-a", Name: "tool_a2", Description: "Tool A2"},
	}
	mgr.tools["server-b"] = []ToolSchema{
		{Server: "server-b", Name: "tool_b1", Description: "Tool B1"},
	}

	tools := mgr.ListAllTools()
	if len(tools) != 3 {
		t.Fatalf("expected 3 tools, got %d", len(tools))
	}

	// サーバー名が正しく設定されているか確認
	names := map[string]bool{}
	for _, tool := range tools {
		names[tool.Name] = true
	}
	for _, expected := range []string{"tool_a1", "tool_a2", "tool_b1"} {
		if !names[expected] {
			t.Errorf("expected tool '%s' in aggregated list", expected)
		}
	}
}

func TestManager_CallTool_Routing(t *testing.T) {
	// 正しいサーバーにルーティングされること
	configs := []ServerConfig{
		{Name: "server-a", Command: "echo"},
	}
	mgr, pairs := newTestManager(t, configs)
	defer func() {
		for _, p := range pairs {
			p.mock.close()
			p.client.Close()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	var result *CallResult
	go func() {
		var err error
		result, err = mgr.CallTool(ctx, "server-a", "my_tool", map[string]any{"key": "value"})
		errCh <- err
	}()

	// モックサーバーでリクエストを処理
	req := pairs[0].mock.readRequest(t)
	if req.Method != "tools/call" {
		t.Fatalf("expected method 'tools/call', got '%s'", req.Method)
	}

	// params を検証
	paramsBytes, _ := json.Marshal(req.Params)
	var params map[string]any
	json.Unmarshal(paramsBytes, &params)
	if params["name"] != "my_tool" {
		t.Errorf("expected tool name 'my_tool', got '%v'", params["name"])
	}

	pairs[0].mock.writeResponse(t, req.ID, map[string]any{
		"content": []map[string]any{
			{"type": "text", "text": "result from server-a"},
		},
	})

	if err := <-errCh; err != nil {
		t.Fatalf("CallTool returned error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.Content[0].Text != "result from server-a" {
		t.Errorf("unexpected result text: '%s'", result.Content[0].Text)
	}
}

func TestManager_CallTool_UnknownServer(t *testing.T) {
	// 存在しないサーバーへのルーティングはエラー
	configs := []ServerConfig{
		{Name: "server-a", Command: "echo"},
	}
	mgr, pairs := newTestManager(t, configs)
	defer func() {
		for _, p := range pairs {
			p.mock.close()
			p.client.Close()
		}
	}()

	ctx := context.Background()
	_, err := mgr.CallTool(ctx, "nonexistent-server", "tool", nil)
	if err == nil {
		t.Fatal("expected error for unknown server")
	}
}

func TestManager_IsProposalRequired(t *testing.T) {
	trueVal := true
	falseVal := false

	configs := []ServerConfig{
		{Name: "safe-server", Command: "echo", ProposalRequired: &trueVal},
		{Name: "fast-server", Command: "echo", ProposalRequired: &falseVal},
		{Name: "default-server", Command: "echo"},
	}
	mgr, pairs := newTestManager(t, configs)
	defer func() {
		for _, p := range pairs {
			p.mock.close()
			p.client.Close()
		}
	}()

	if !mgr.IsProposalRequired("safe-server") {
		t.Error("expected proposal required for safe-server")
	}
	if mgr.IsProposalRequired("fast-server") {
		t.Error("expected proposal not required for fast-server")
	}
	if mgr.IsProposalRequired("default-server") {
		t.Error("expected proposal not required for default-server (default)")
	}
	if mgr.IsProposalRequired("unknown-server") {
		t.Error("expected proposal not required for unknown server")
	}
}

func TestManager_Close(t *testing.T) {
	configs := []ServerConfig{
		{Name: "server-a", Command: "echo"},
		{Name: "server-b", Command: "echo"},
	}
	mgr, _ := newTestManager(t, configs)

	// Close はエラーなく完了するべき
	err := mgr.Close()
	if err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	// Close 後の CallTool はエラー
	ctx := context.Background()
	_, err = mgr.CallTool(ctx, "server-a", "tool", nil)
	if err == nil {
		t.Error("expected error after Close")
	}
}

func TestManager_NewManager_InvalidYAML(t *testing.T) {
	// 不正な YAML ファイルの場合はエラーを返す
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp.yaml")
	if err := os.WriteFile(path, []byte("{{{invalid yaml"), 0644); err != nil {
		t.Fatal(err)
	}

	m, err := NewManager(path)
	if err == nil {
		t.Fatal("expected error for invalid YAML config")
	}
	if m != nil {
		t.Error("expected nil manager on error")
	}
}

func TestManager_StartAllWithClients_InitializeFailure(t *testing.T) {
	// Initialize が失敗するサーバーは除外されてエラーにならない
	configs := []ServerConfig{
		{Name: "failing-server", Command: "echo"},
		{Name: "ok-server", Command: "echo"},
	}
	mgr, pairs := newTestManager(t, configs)
	defer func() {
		for _, p := range pairs {
			p.mock.close()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- mgr.startAllWithClients(ctx)
	}()

	// failing-server: initialize リクエストを読み取ってエラーレスポンスを返す
	req1 := pairs[0].mock.readRequest(t)
	pairs[0].mock.writeErrorResponse(t, req1.ID, -32600, "initialization failed")

	// ok-server: 正常に処理
	req2 := pairs[1].mock.readRequest(t)
	pairs[1].mock.writeResponse(t, req2.ID, map[string]any{
		"protocolVersion": "2024-11-05",
		"capabilities":    map[string]any{},
		"serverInfo":      map[string]any{"name": "ok", "version": "1.0"},
	})
	notif := pairs[1].mock.readNotification(t)
	if notif["method"] != "notifications/initialized" {
		t.Fatalf("expected notifications/initialized, got '%v'", notif["method"])
	}
	req3 := pairs[1].mock.readRequest(t)
	pairs[1].mock.writeResponse(t, req3.ID, map[string]any{
		"tools": []map[string]any{
			{"name": "ok_tool", "description": "works", "inputSchema": map[string]any{"type": "object"}},
		},
	})

	if err := <-errCh; err != nil {
		t.Fatalf("startAllWithClients returned error: %v", err)
	}

	// failing-server はクライアントから除外されていること
	if _, ok := mgr.clients["failing-server"]; ok {
		t.Error("expected failing-server to be removed from clients")
	}

	// ok-server のツールは登録されていること
	tools := mgr.ListAllTools()
	if len(tools) != 1 {
		t.Fatalf("expected 1 tool, got %d", len(tools))
	}
	if tools[0].Name != "ok_tool" {
		t.Errorf("expected tool 'ok_tool', got '%s'", tools[0].Name)
	}
	if tools[0].Server != "ok-server" {
		t.Errorf("expected server 'ok-server', got '%s'", tools[0].Server)
	}
}

func TestManager_StartAllWithClients_ListToolsFailure(t *testing.T) {
	// Initialize は成功するが ListTools が失敗するサーバー
	configs := []ServerConfig{
		{Name: "list-fail-server", Command: "echo"},
	}
	mgr, pairs := newTestManager(t, configs)
	defer func() {
		for _, p := range pairs {
			p.mock.close()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- mgr.startAllWithClients(ctx)
	}()

	mock := pairs[0].mock

	// Initialize: 正常処理
	req := mock.readRequest(t)
	mock.writeResponse(t, req.ID, map[string]any{
		"protocolVersion": "2024-11-05",
		"capabilities":    map[string]any{},
		"serverInfo":      map[string]any{"name": "test", "version": "1.0"},
	})
	_ = mock.readNotification(t)

	// ListTools: エラーレスポンスを返す
	req = mock.readRequest(t)
	mock.writeErrorResponse(t, req.ID, -32601, "tools/list not supported")

	if err := <-errCh; err != nil {
		t.Fatalf("startAllWithClients returned error: %v", err)
	}

	// サーバーはクライアントから除外されていること
	if _, ok := mgr.clients["list-fail-server"]; ok {
		t.Error("expected list-fail-server to be removed from clients")
	}

	// ツールは登録されていないこと
	tools := mgr.ListAllTools()
	if len(tools) != 0 {
		t.Errorf("expected 0 tools, got %d", len(tools))
	}
}

func TestManager_StartAllWithClients_MissingClient(t *testing.T) {
	// configs にあるがクライアントが注入されていないサーバーはスキップされる
	configs := []ServerConfig{
		{Name: "missing-server", Command: "echo"},
	}
	mgr := &MCPManager{
		clients: make(map[string]*MCPClient), // 空: クライアントなし
		configs: configs,
		tools:   make(map[string][]ToolSchema),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := mgr.startAllWithClients(ctx)
	if err != nil {
		t.Fatalf("startAllWithClients returned error: %v", err)
	}

	// ツールは登録されていないこと
	tools := mgr.ListAllTools()
	if len(tools) != 0 {
		t.Errorf("expected 0 tools, got %d", len(tools))
	}
}

func TestManager_Close_NoClients(t *testing.T) {
	// クライアントがない場合の Close
	mgr := &MCPManager{
		clients: make(map[string]*MCPClient),
		configs: nil,
		tools:   make(map[string][]ToolSchema),
	}

	err := mgr.Close()
	if err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
}

func TestManager_Close_MultipleClients(t *testing.T) {
	// 複数クライアントが正常に Close されること
	configs := []ServerConfig{
		{Name: "server-a", Command: "echo"},
		{Name: "server-b", Command: "echo"},
	}
	mgr, _ := newTestManager(t, configs)

	err := mgr.Close()
	if err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	// Close 後はクライアントが空になっていること
	if len(mgr.clients) != 0 {
		t.Errorf("expected 0 clients after Close, got %d", len(mgr.clients))
	}
}

func TestManager_StartAll_WithMock(t *testing.T) {
	// StartAll がイニシャライズとツール一覧取得を行うことを確認
	configs := []ServerConfig{
		{Name: "mock-server", Command: "echo"},
	}
	mgr, pairs := newTestManager(t, configs)
	defer func() {
		for _, p := range pairs {
			p.mock.close()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- mgr.startAllWithClients(ctx)
	}()

	mock := pairs[0].mock

	// 1. initialize リクエストを処理
	req := mock.readRequest(t)
	if req.Method != "initialize" {
		t.Fatalf("expected method 'initialize', got '%s'", req.Method)
	}
	mock.writeResponse(t, req.ID, map[string]any{
		"protocolVersion": "2024-11-05",
		"capabilities":    map[string]any{},
		"serverInfo":      map[string]any{"name": "mock", "version": "1.0"},
	})

	// 2. notifications/initialized を読み取る
	notif := mock.readNotification(t)
	if notif["method"] != "notifications/initialized" {
		t.Fatalf("expected notifications/initialized, got '%v'", notif["method"])
	}

	// 3. tools/list リクエストを処理
	req = mock.readRequest(t)
	if req.Method != "tools/list" {
		t.Fatalf("expected method 'tools/list', got '%s'", req.Method)
	}
	mock.writeResponse(t, req.ID, map[string]any{
		"tools": []map[string]any{
			{
				"name":        "mock_tool",
				"description": "A mock tool",
				"inputSchema": map[string]any{"type": "object"},
			},
		},
	})

	if err := <-errCh; err != nil {
		t.Fatalf("startAllWithClients returned error: %v", err)
	}

	// ツールが正しく登録されたか確認
	tools := mgr.ListAllTools()
	if len(tools) != 1 {
		t.Fatalf("expected 1 tool, got %d", len(tools))
	}
	if tools[0].Name != "mock_tool" {
		t.Errorf("expected tool name 'mock_tool', got '%s'", tools[0].Name)
	}
	if tools[0].Server != "mock-server" {
		t.Errorf("expected server 'mock-server', got '%s'", tools[0].Server)
	}
}
