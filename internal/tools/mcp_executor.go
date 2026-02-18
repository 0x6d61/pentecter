package tools

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// MCPExecutor は MCP サーバー（stdio または HTTP SSE）経由でツールを実行する Executor。
// MCP サーバーへの接続に失敗した場合、呼び出し元（Registry）が YAML にフォールバックする。
type MCPExecutor struct {
	def      MCPServerDef
	toolName string // MCP サーバー内のツール名（省略時は def.Tool と同じ）
	client   *http.Client
}

func newMCPExecutor(def MCPServerDef) *MCPExecutor {
	return &MCPExecutor{
		def:      def,
		toolName: def.Tool,
		client:   &http.Client{Timeout: 120 * time.Second},
	}
}

func (e *MCPExecutor) ExecutorType() string { return "mcp" }

// Execute は MCP サーバーにツール呼び出しを送り、レスポンスを OutputLine としてストリームする。
func (e *MCPExecutor) Execute(ctx context.Context, store *LogStore, args map[string]any) (<-chan OutputLine, <-chan *ToolResult) {
	linesCh := make(chan OutputLine, 256)
	resultCh := make(chan *ToolResult, 1)

	go func() {
		defer close(linesCh)
		defer close(resultCh)
		var res *ToolResult
		switch e.def.Transport {
		case MCPTransportHTTP:
			res = e.callHTTP(ctx, args, linesCh)
		case MCPTransportStdio:
			res = e.callStdio(ctx, args, linesCh)
		default:
			res = &ToolResult{
				ToolName: e.def.Tool,
				Err:      fmt.Errorf("unknown MCP transport: %q", e.def.Transport),
			}
		}
		store.Save(res)
		resultCh <- res
	}()

	return linesCh, resultCh
}

// --- HTTP SSE 実装 ---

// mcpJSONRPC は MCP の JSON-RPC 2.0 リクエスト構造体。
type mcpJSONRPC struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Method  string `json:"method"`
	Params  any    `json:"params"`
}

func (e *MCPExecutor) callHTTP(ctx context.Context, args map[string]any, linesCh chan<- OutputLine) *ToolResult {
	startedAt := time.Now()
	id := MakeID(e.def.Tool, "mcp-http", startedAt)

	// MCP tools/call リクエストを組み立てる
	payload := mcpJSONRPC{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
		Params: map[string]any{
			"name":      e.toolName,
			"arguments": args,
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return &ToolResult{ID: id, ToolName: e.def.Tool, StartedAt: startedAt,
			FinishedAt: time.Now(), Err: fmt.Errorf("mcp marshal: %w", err)}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.def.URL, bytes.NewReader(body))
	if err != nil {
		return &ToolResult{ID: id, ToolName: e.def.Tool, StartedAt: startedAt,
			FinishedAt: time.Now(), Err: fmt.Errorf("mcp request: %w", err)}
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")
	for k, v := range e.def.Headers {
		req.Header.Set(k, v)
	}

	resp, err := e.client.Do(req)
	if err != nil {
		return &ToolResult{ID: id, ToolName: e.def.Tool, StartedAt: startedAt,
			FinishedAt: time.Now(), Err: fmt.Errorf("mcp connect: %w", err)}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return &ToolResult{ID: id, ToolName: e.def.Tool, StartedAt: startedAt,
			FinishedAt: time.Now(), Err: fmt.Errorf("mcp HTTP %d: %s", resp.StatusCode, string(b))}
	}

	rawLines := e.readSSEStream(ctx, resp.Body, linesCh)
	rawTextLines := make([]string, len(rawLines))
	for i, l := range rawLines {
		rawTextLines[i] = l.Content
	}

	return &ToolResult{
		ID:         id,
		ToolName:   e.def.Tool,
		RawLines:   rawLines,
		Truncated:  strings.Join(rawTextLines, "\n"),
		Entities:   ExtractEntities(rawTextLines),
		StartedAt:  startedAt,
		FinishedAt: time.Now(),
	}
}

// readSSEStream は HTTP SSE ストリームを読み込み、data: 行を OutputLine に変換する。
func (e *MCPExecutor) readSSEStream(ctx context.Context, r io.Reader, linesCh chan<- OutputLine) []OutputLine {
	var rawLines []OutputLine
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return rawLines
		default:
		}
		text := scanner.Text()
		if !strings.HasPrefix(text, "data:") {
			continue
		}
		content := strings.TrimPrefix(text, "data:")
		content = strings.TrimSpace(content)
		if content == "" || content == "[DONE]" {
			continue
		}
		line := OutputLine{Time: time.Now(), Content: content}
		rawLines = append(rawLines, line)
		select {
		case linesCh <- line:
		case <-ctx.Done():
			return rawLines
		}
	}
	return rawLines
}

// --- stdio 実装 ---

func (e *MCPExecutor) callStdio(ctx context.Context, args map[string]any, linesCh chan<- OutputLine) *ToolResult {
	startedAt := time.Now()
	id := MakeID(e.def.Tool, "mcp-stdio", startedAt)

	absPath, err := resolveBinary(e.def.Command)
	if err != nil {
		return &ToolResult{ID: id, ToolName: e.def.Tool, StartedAt: startedAt,
			FinishedAt: time.Now(), Err: fmt.Errorf("mcp stdio binary: %w", err)}
	}

	cmd := exec.CommandContext(ctx, absPath, e.def.Args...) // nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command -- absPath は LookPath で検証済み
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()

	if err := cmd.Start(); err != nil {
		return &ToolResult{ID: id, ToolName: e.def.Tool, StartedAt: startedAt,
			FinishedAt: time.Now(), Err: fmt.Errorf("mcp stdio start: %w", err)}
	}

	// 初期化 → ツール呼び出しの JSON-RPC を順に送る
	reqs := []mcpJSONRPC{
		{JSONRPC: "2.0", ID: 1, Method: "initialize", Params: map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]string{"name": "pentecter", "version": "0.1"},
		}},
		{JSONRPC: "2.0", ID: 2, Method: "tools/call", Params: map[string]any{
			"name":      e.toolName,
			"arguments": args,
		}},
	}

	var mu sync.Mutex
	var rawLines []OutputLine

	// 応答を読むゴルーチン
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := OutputLine{Time: time.Now(), Content: scanner.Text()}
			mu.Lock()
			rawLines = append(rawLines, line)
			mu.Unlock()
			select {
			case linesCh <- line:
			case <-ctx.Done():
				return
			}
		}
	}()

	// リクエストを送信
	enc := json.NewEncoder(stdin)
	for _, req := range reqs {
		if err := enc.Encode(req); err != nil {
			break
		}
	}
	stdin.Close()

	<-readDone
	cmd.Wait() //nolint:errcheck

	mu.Lock()
	lines := rawLines
	mu.Unlock()

	rawTextLines := make([]string, len(lines))
	for i, l := range lines {
		rawTextLines[i] = l.Content
	}

	return &ToolResult{
		ID:         id,
		ToolName:   e.def.Tool,
		RawLines:   lines,
		Truncated:  strings.Join(rawTextLines, "\n"),
		Entities:   ExtractEntities(rawTextLines),
		StartedAt:  startedAt,
		FinishedAt: time.Now(),
	}
}
