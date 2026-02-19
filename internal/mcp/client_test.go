package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"
)

// mockMCPServer はテスト用のモック MCP サーバーをシミュレートする。
// クライアントの stdin に書き込まれた JSON-RPC リクエストを読み取り、
// クライアントの stdout へ JSON-RPC レスポンスを返す。
type mockMCPServer struct {
	// clientStdinReader はクライアントが stdin に書き込んだデータを読み取る側
	clientStdinReader io.ReadCloser
	// clientStdoutWriter はクライアントの stdout へデータを書き込む側
	clientStdoutWriter io.WriteCloser
	scanner            *bufio.Scanner
}

// newMockMCPServer はパイプベースのモック MCP サーバーを作成し、
// テスト用の MCPClient とともに返す。
func newMockMCPServer(t *testing.T) (*mockMCPServer, *MCPClient) {
	t.Helper()

	// クライアント stdin: クライアントが書く → サーバーが読む
	stdinReader, stdinWriter := io.Pipe()
	// クライアント stdout: サーバーが書く → クライアントが読む
	stdoutReader, stdoutWriter := io.Pipe()

	mock := &mockMCPServer{
		clientStdinReader:  stdinReader,
		clientStdoutWriter: stdoutWriter,
		scanner:            bufio.NewScanner(stdinReader),
	}

	client := newClientFromPipes(stdinWriter, stdoutReader)

	return mock, client
}

// readRequest はクライアントから1行の JSON-RPC リクエストを読み取る
func (m *mockMCPServer) readRequest(t *testing.T) jsonRPCRequest {
	t.Helper()
	if !m.scanner.Scan() {
		t.Fatal("mock server: failed to read request from client stdin")
	}
	var req jsonRPCRequest
	if err := json.Unmarshal(m.scanner.Bytes(), &req); err != nil {
		t.Fatalf("mock server: failed to parse request: %v, raw: %s", err, m.scanner.Text())
	}
	return req
}

// readNotification はクライアントから通知（id なし）を読み取る
func (m *mockMCPServer) readNotification(t *testing.T) map[string]any {
	t.Helper()
	if !m.scanner.Scan() {
		t.Fatal("mock server: failed to read notification from client stdin")
	}
	var msg map[string]any
	if err := json.Unmarshal(m.scanner.Bytes(), &msg); err != nil {
		t.Fatalf("mock server: failed to parse notification: %v", err)
	}
	return msg
}

// writeResponse はクライアントの stdout へ JSON-RPC レスポンスを書き込む
func (m *mockMCPServer) writeResponse(t *testing.T, id int64, result any) {
	t.Helper()
	resultBytes, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("mock server: failed to marshal result: %v", err)
	}
	resp := jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  json.RawMessage(resultBytes),
	}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("mock server: failed to marshal response: %v", err)
	}
	data = append(data, '\n')
	if _, err := m.clientStdoutWriter.Write(data); err != nil {
		t.Fatalf("mock server: failed to write response: %v", err)
	}
}

// writeErrorResponse はクライアントの stdout へ JSON-RPC エラーレスポンスを書き込む
func (m *mockMCPServer) writeErrorResponse(t *testing.T, id int64, code int, message string) {
	t.Helper()
	resp := jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error: &jsonRPCError{
			Code:    code,
			Message: message,
		},
	}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("mock server: failed to marshal error response: %v", err)
	}
	data = append(data, '\n')
	if _, err := m.clientStdoutWriter.Write(data); err != nil {
		t.Fatalf("mock server: failed to write error response: %v", err)
	}
}

// close はモックサーバーのリソースを解放する
func (m *mockMCPServer) close() {
	m.clientStdinReader.Close()
	m.clientStdoutWriter.Close()
}

func TestClient_Initialize(t *testing.T) {
	mock, client := newMockMCPServer(t)
	defer mock.close()
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Initialize を非同期で呼び出す
	errCh := make(chan error, 1)
	go func() {
		errCh <- client.Initialize(ctx)
	}()

	// initialize リクエストを読み取る
	req := mock.readRequest(t)
	if req.Method != "initialize" {
		t.Fatalf("expected method 'initialize', got '%s'", req.Method)
	}
	if req.JSONRPC != "2.0" {
		t.Fatalf("expected jsonrpc '2.0', got '%s'", req.JSONRPC)
	}

	// params を検証
	paramsBytes, _ := json.Marshal(req.Params)
	var params map[string]any
	json.Unmarshal(paramsBytes, &params)
	if params["protocolVersion"] != "2024-11-05" {
		t.Errorf("expected protocolVersion '2024-11-05', got '%v'", params["protocolVersion"])
	}
	clientInfo, ok := params["clientInfo"].(map[string]any)
	if !ok {
		t.Fatal("expected clientInfo in params")
	}
	if clientInfo["name"] != "pentecter" {
		t.Errorf("expected clientInfo.name 'pentecter', got '%v'", clientInfo["name"])
	}

	// initialize レスポンスを返す
	mock.writeResponse(t, req.ID, map[string]any{
		"protocolVersion": "2024-11-05",
		"capabilities":    map[string]any{},
		"serverInfo": map[string]any{
			"name":    "test-server",
			"version": "1.0.0",
		},
	})

	// notifications/initialized を読み取る
	notif := mock.readNotification(t)
	if notif["method"] != "notifications/initialized" {
		t.Fatalf("expected method 'notifications/initialized', got '%v'", notif["method"])
	}
	// 通知には id がないことを確認
	if _, hasID := notif["id"]; hasID {
		t.Error("notification should not have id field")
	}

	// Initialize が成功したことを確認
	if err := <-errCh; err != nil {
		t.Fatalf("Initialize returned error: %v", err)
	}
}

func TestClient_ListTools(t *testing.T) {
	mock, client := newMockMCPServer(t)
	defer mock.close()
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	var tools []ToolSchema
	go func() {
		var err error
		tools, err = client.ListTools(ctx)
		errCh <- err
	}()

	// tools/list リクエストを読み取る
	req := mock.readRequest(t)
	if req.Method != "tools/list" {
		t.Fatalf("expected method 'tools/list', got '%s'", req.Method)
	}

	// レスポンスを返す
	mock.writeResponse(t, req.ID, map[string]any{
		"tools": []map[string]any{
			{
				"name":        "browser_navigate",
				"description": "Navigate to a URL",
				"inputSchema": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"url": map[string]any{
							"type":        "string",
							"description": "URL to navigate to",
						},
					},
					"required": []string{"url"},
				},
			},
			{
				"name":        "browser_click",
				"description": "Click an element",
				"inputSchema": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"selector": map[string]any{
							"type": "string",
						},
					},
				},
			},
		},
	})

	if err := <-errCh; err != nil {
		t.Fatalf("ListTools returned error: %v", err)
	}

	if len(tools) != 2 {
		t.Fatalf("expected 2 tools, got %d", len(tools))
	}
	if tools[0].Name != "browser_navigate" {
		t.Errorf("expected tool name 'browser_navigate', got '%s'", tools[0].Name)
	}
	if tools[0].Description != "Navigate to a URL" {
		t.Errorf("unexpected description: '%s'", tools[0].Description)
	}
	if tools[1].Name != "browser_click" {
		t.Errorf("expected tool name 'browser_click', got '%s'", tools[1].Name)
	}
}

func TestClient_CallTool(t *testing.T) {
	mock, client := newMockMCPServer(t)
	defer mock.close()
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	var result *CallResult
	go func() {
		var err error
		result, err = client.CallTool(ctx, "browser_navigate", map[string]any{
			"url": "https://example.com",
		})
		errCh <- err
	}()

	// tools/call リクエストを読み取る
	req := mock.readRequest(t)
	if req.Method != "tools/call" {
		t.Fatalf("expected method 'tools/call', got '%s'", req.Method)
	}

	// params を検証
	paramsBytes, _ := json.Marshal(req.Params)
	var params map[string]any
	json.Unmarshal(paramsBytes, &params)
	if params["name"] != "browser_navigate" {
		t.Errorf("expected tool name 'browser_navigate', got '%v'", params["name"])
	}
	args, ok := params["arguments"].(map[string]any)
	if !ok {
		t.Fatal("expected arguments in params")
	}
	if args["url"] != "https://example.com" {
		t.Errorf("expected url 'https://example.com', got '%v'", args["url"])
	}

	// レスポンスを返す
	mock.writeResponse(t, req.ID, map[string]any{
		"content": []map[string]any{
			{
				"type": "text",
				"text": "Navigated to https://example.com",
			},
		},
		"isError": false,
	})

	if err := <-errCh; err != nil {
		t.Fatalf("CallTool returned error: %v", err)
	}

	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if len(result.Content) != 1 {
		t.Fatalf("expected 1 content block, got %d", len(result.Content))
	}
	if result.Content[0].Type != "text" {
		t.Errorf("expected content type 'text', got '%s'", result.Content[0].Type)
	}
	if result.Content[0].Text != "Navigated to https://example.com" {
		t.Errorf("unexpected text: '%s'", result.Content[0].Text)
	}
	if result.IsError {
		t.Error("expected isError=false")
	}
}

func TestClient_CallTool_Error(t *testing.T) {
	mock, client := newMockMCPServer(t)
	defer mock.close()
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		_, err := client.CallTool(ctx, "nonexistent_tool", nil)
		errCh <- err
	}()

	req := mock.readRequest(t)
	// JSON-RPC エラーレスポンスを返す
	mock.writeErrorResponse(t, req.ID, -32601, "Method not found")

	err := <-errCh
	if err == nil {
		t.Fatal("expected error for JSON-RPC error response")
	}
	if !strings.Contains(err.Error(), "Method not found") {
		t.Errorf("expected error to contain 'Method not found', got: %v", err)
	}
}

func TestClient_CallTool_ToolError(t *testing.T) {
	// ツール自体がエラーを返した場合（isError=true）
	mock, client := newMockMCPServer(t)
	defer mock.close()
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	var result *CallResult
	go func() {
		var err error
		result, err = client.CallTool(ctx, "browser_navigate", map[string]any{
			"url": "invalid://url",
		})
		errCh <- err
	}()

	req := mock.readRequest(t)
	mock.writeResponse(t, req.ID, map[string]any{
		"content": []map[string]any{
			{
				"type": "text",
				"text": "Invalid URL format",
			},
		},
		"isError": true,
	})

	if err := <-errCh; err != nil {
		t.Fatalf("CallTool returned error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if !result.IsError {
		t.Error("expected isError=true")
	}
	if result.Content[0].Text != "Invalid URL format" {
		t.Errorf("unexpected error text: '%s'", result.Content[0].Text)
	}
}

func TestClient_Close(t *testing.T) {
	mock, client := newMockMCPServer(t)
	_ = mock // mock のクリーンアップはクライアント側で行う

	err := client.Close()
	if err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	// Close 後の呼び出しはエラーになるべき
	ctx := context.Background()
	_, err = client.ListTools(ctx)
	if err == nil {
		t.Error("expected error when calling ListTools after Close")
	}
}

func TestClient_ContextCancellation(t *testing.T) {
	mock, client := newMockMCPServer(t)
	defer mock.close()
	defer client.Close()

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- client.Initialize(ctx)
	}()

	// リクエストが送信されるのを待つ
	_ = mock.readRequest(t)

	// レスポンスを返す前にキャンセル
	cancel()

	err := <-errCh
	if err == nil {
		t.Fatal("expected error on context cancellation")
	}
}

func TestClient_SkipNonJSONBanner(t *testing.T) {
	// MCP サーバーが stdout にバナー行を出力しても正常に動作することを確認
	mock, client := newMockMCPServer(t)
	defer mock.close()
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	var tools []ToolSchema
	go func() {
		var err error
		tools, err = client.ListTools(ctx)
		errCh <- err
	}()

	// リクエストを読み取る
	req := mock.readRequest(t)
	if req.Method != "tools/list" {
		t.Fatalf("expected method 'tools/list', got '%s'", req.Method)
	}

	// バナー行を先に書き込む（MCP サーバーのバナー出力をシミュレート）
	bannerLines := []string{
		"HackTricks MCP Server v1.3.0 running on stdio\n",
		"Loading knowledge base...\n",
		"\n", // 空行
	}
	for _, line := range bannerLines {
		if _, err := mock.clientStdoutWriter.Write([]byte(line)); err != nil {
			t.Fatalf("failed to write banner: %v", err)
		}
	}

	// その後に正規の JSON-RPC レスポンスを返す
	mock.writeResponse(t, req.ID, map[string]any{
		"tools": []map[string]any{
			{
				"name":        "search_hacktricks",
				"description": "Search HackTricks knowledge base",
				"inputSchema": map[string]any{
					"type":       "object",
					"properties": map[string]any{},
				},
			},
		},
	})

	if err := <-errCh; err != nil {
		t.Fatalf("ListTools returned error: %v", err)
	}

	if len(tools) != 1 {
		t.Fatalf("expected 1 tool, got %d", len(tools))
	}
	if tools[0].Name != "search_hacktricks" {
		t.Errorf("expected tool name 'search_hacktricks', got '%s'", tools[0].Name)
	}
}

func TestClient_IncrementingIDs(t *testing.T) {
	// 連続したリクエストで ID がインクリメントされることを確認
	mock, client := newMockMCPServer(t)
	defer mock.close()
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 1つ目のリクエスト
	go func() {
		client.ListTools(ctx) //nolint:errcheck
	}()
	req1 := mock.readRequest(t)

	// 2つ目のリクエスト（1つ目のレスポンスを返してから）
	mock.writeResponse(t, req1.ID, map[string]any{"tools": []any{}})
	// 少し待ってから次のリクエスト
	time.Sleep(50 * time.Millisecond)

	go func() {
		client.ListTools(ctx) //nolint:errcheck
	}()
	req2 := mock.readRequest(t)
	mock.writeResponse(t, req2.ID, map[string]any{"tools": []any{}})

	if req2.ID <= req1.ID {
		t.Errorf("expected incrementing IDs: first=%d, second=%d", req1.ID, req2.ID)
	}
}
