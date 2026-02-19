package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"
)

// JSON-RPC 2.0 メッセージ型

type jsonRPCRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int64  `json:"id,omitempty"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

type jsonRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int64           `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *jsonRPCError   `json:"error,omitempty"`
}

type jsonRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// MCPClient は MCP サーバーとの JSON-RPC 2.0 over stdio 通信を管理する
type MCPClient struct {
	stdin   io.WriteCloser
	stdout  io.ReadCloser
	scanner *bufio.Scanner
	cmd     *exec.Cmd // サブプロセスモード時のみ非 nil

	mu     sync.Mutex // stdin/stdout 操作の排他制御
	nextID atomic.Int64
	closed atomic.Bool
}

// NewStdioClient は MCP サーバーをサブプロセスとして起動し、クライアントを返す。
// env は "KEY=VALUE" 形式の環境変数リスト。
func NewStdioClient(command string, args []string, env []string) (*MCPClient, error) {
	cmd := exec.Command(command, args...) // nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command -- command は管理者が設定した mcp.yaml から読み込まれる（ユーザー入力ではない）
	if len(env) > 0 {
		cmd.Env = env
	}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("mcp: failed to create stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return nil, fmt.Errorf("mcp: failed to create stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		return nil, fmt.Errorf("mcp: failed to start server %s: %w", command, err)
	}

	c := &MCPClient{
		stdin:   stdin,
		stdout:  stdout,
		scanner: bufio.NewScanner(stdout),
		cmd:     cmd,
	}
	return c, nil
}

// newClientFromPipes はテスト用に io.Pipe ベースのクライアントを作成する
func newClientFromPipes(stdin io.WriteCloser, stdout io.ReadCloser) *MCPClient {
	return &MCPClient{
		stdin:   stdin,
		stdout:  stdout,
		scanner: bufio.NewScanner(stdout),
	}
}

// Initialize は MCP プロトコルのハンドシェイクを行う。
// initialize リクエスト → レスポンス受信 → notifications/initialized 通知の順に実行する。
func (c *MCPClient) Initialize(ctx context.Context) error {
	if c.closed.Load() {
		return fmt.Errorf("mcp: client is closed")
	}

	// initialize リクエスト送信
	result, err := c.sendRequest(ctx, "initialize", map[string]any{
		"protocolVersion": "2024-11-05",
		"capabilities":    map[string]any{},
		"clientInfo": map[string]any{
			"name":    "pentecter",
			"version": "0.1.0",
		},
	})
	if err != nil {
		return fmt.Errorf("mcp: initialize failed: %w", err)
	}
	_ = result // サーバーの capabilities は現時点では使わない

	// notifications/initialized 通知を送信（id なし）
	if err := c.sendNotification("notifications/initialized"); err != nil {
		return fmt.Errorf("mcp: failed to send initialized notification: %w", err)
	}

	return nil
}

// ListTools は MCP サーバーからツール一覧を取得する
func (c *MCPClient) ListTools(ctx context.Context) ([]ToolSchema, error) {
	if c.closed.Load() {
		return nil, fmt.Errorf("mcp: client is closed")
	}

	result, err := c.sendRequest(ctx, "tools/list", nil)
	if err != nil {
		return nil, fmt.Errorf("mcp: tools/list failed: %w", err)
	}

	// レスポンスの tools フィールドをパース
	var resp struct {
		Tools []ToolSchema `json:"tools"`
	}
	if err := json.Unmarshal(result, &resp); err != nil {
		return nil, fmt.Errorf("mcp: failed to parse tools/list response: %w", err)
	}

	return resp.Tools, nil
}

// CallTool は MCP サーバーのツールを呼び出す
func (c *MCPClient) CallTool(ctx context.Context, name string, args map[string]any) (*CallResult, error) {
	if c.closed.Load() {
		return nil, fmt.Errorf("mcp: client is closed")
	}

	params := map[string]any{
		"name": name,
	}
	if args != nil {
		params["arguments"] = args
	}

	result, err := c.sendRequest(ctx, "tools/call", params)
	if err != nil {
		return nil, fmt.Errorf("mcp: tools/call failed: %w", err)
	}

	var callResult CallResult
	if err := json.Unmarshal(result, &callResult); err != nil {
		return nil, fmt.Errorf("mcp: failed to parse tools/call response: %w", err)
	}

	return &callResult, nil
}

// Close はクライアントを閉じ、サブプロセスを終了させる
func (c *MCPClient) Close() error {
	if c.closed.Swap(true) {
		return nil // 既に閉じている
	}

	// stdin を閉じてサーバーに EOF を通知
	_ = c.stdin.Close()
	_ = c.stdout.Close()

	// サブプロセスがある場合は待機（タイムアウト付き）
	if c.cmd != nil {
		done := make(chan error, 1)
		go func() {
			done <- c.cmd.Wait()
		}()

		select {
		case <-done:
			// 正常終了
		case <-time.After(5 * time.Second):
			// タイムアウト — プロセスを強制終了
			_ = c.cmd.Process.Kill()
			<-done
		}
	}

	return nil
}

// sendRequest は JSON-RPC リクエストを送信し、レスポンスを待つ
func (c *MCPClient) sendRequest(ctx context.Context, method string, params any) (json.RawMessage, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	id := c.nextID.Add(1)

	req := jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      id,
		Method:  method,
		Params:  params,
	}

	// リクエストを送信
	data, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}
	data = append(data, '\n')

	if _, err := c.stdin.Write(data); err != nil {
		return nil, fmt.Errorf("failed to write request: %w", err)
	}

	// レスポンスを読み取る（コンテキストキャンセル対応）
	type scanResult struct {
		resp jsonRPCResponse
		err  error
	}
	ch := make(chan scanResult, 1)
	go func() {
		for {
			if !c.scanner.Scan() {
				err := c.scanner.Err()
				if err == nil {
					err = fmt.Errorf("unexpected EOF")
				}
				ch <- scanResult{err: err}
				return
			}
			line := c.scanner.Bytes()
			// 非 JSON 行（MCP サーバーのバナー出力等）をスキップ
			if len(line) == 0 || line[0] != '{' {
				continue
			}
			var resp jsonRPCResponse
			if err := json.Unmarshal(line, &resp); err != nil {
				ch <- scanResult{err: fmt.Errorf("failed to parse response: %w", err)}
				return
			}
			ch <- scanResult{resp: resp}
			return
		}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case sr := <-ch:
		if sr.err != nil {
			return nil, sr.err
		}
		if sr.resp.Error != nil {
			return nil, fmt.Errorf("JSON-RPC error %d: %s", sr.resp.Error.Code, sr.resp.Error.Message)
		}
		return sr.resp.Result, nil
	}
}

// sendNotification は JSON-RPC 通知を送信する（id なし、レスポンス不要）
func (c *MCPClient) sendNotification(method string) error {
	// 通知は id フィールドを含まない
	msg := map[string]any{
		"jsonrpc": "2.0",
		"method":  method,
	}

	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal notification: %w", err)
	}
	data = append(data, '\n')

	if _, err := c.stdin.Write(data); err != nil {
		return fmt.Errorf("failed to write notification: %w", err)
	}

	return nil
}
