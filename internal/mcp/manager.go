package mcp

import (
	"context"
	"fmt"
	"log"
	"os"
)

// MCPManager は複数の MCP サーバーを管理し、ツールの集約・ルーティングを行う
type MCPManager struct {
	clients map[string]*MCPClient   // サーバー名 → クライアント
	configs []ServerConfig          // 設定されたサーバー一覧
	tools   map[string][]ToolSchema // サーバー名 → ツール一覧
}

// NewManager は設定ファイルからマネージャーを作成する。
// 設定ファイルが存在しない場合は nil, nil を返す（graceful skip）。
func NewManager(configPath string) (*MCPManager, error) {
	cfg, err := LoadConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("mcp: failed to load config: %w", err)
	}
	if cfg == nil {
		return nil, nil
	}

	return &MCPManager{
		clients: make(map[string]*MCPClient),
		configs: cfg.Servers,
		tools:   make(map[string][]ToolSchema),
	}, nil
}

// StartAll は全サーバーを起動し、Initialize と ListTools を実行する。
// 個別のサーバー起動に失敗した場合はログに警告を出して続行する。
func (m *MCPManager) StartAll(ctx context.Context) error {
	for _, cfg := range m.configs {
		// 環境変数を "KEY=VALUE" 形式に変換
		var env []string
		if len(cfg.Env) > 0 {
			// ホスト環境を引き継ぎつつ追加する
			env = os.Environ()
			for k, v := range cfg.Env {
				env = append(env, k+"="+v)
			}
		}

		client, err := NewStdioClient(cfg.Command, cfg.Args, env)
		if err != nil {
			log.Printf("[mcp] WARNING: failed to start server %q: %v", cfg.Name, err)
			continue
		}
		m.clients[cfg.Name] = client

		// Initialize ハンドシェイク
		if err := client.Initialize(ctx); err != nil {
			log.Printf("[mcp] WARNING: failed to initialize server %q: %v", cfg.Name, err)
			_ = client.Close()
			delete(m.clients, cfg.Name)
			continue
		}

		// ツール一覧を取得
		tools, err := client.ListTools(ctx)
		if err != nil {
			log.Printf("[mcp] WARNING: failed to list tools from server %q: %v", cfg.Name, err)
			_ = client.Close()
			delete(m.clients, cfg.Name)
			continue
		}

		// サーバー名を各ツールに設定
		for i := range tools {
			tools[i].Server = cfg.Name
		}
		m.tools[cfg.Name] = tools
	}

	return nil
}

// startAllWithClients は既に注入済みのクライアントに対して Initialize と ListTools を実行する。
// テスト用のメソッド。
func (m *MCPManager) startAllWithClients(ctx context.Context) error {
	for _, cfg := range m.configs {
		client, ok := m.clients[cfg.Name]
		if !ok {
			continue
		}

		// Initialize ハンドシェイク
		if err := client.Initialize(ctx); err != nil {
			log.Printf("[mcp] WARNING: failed to initialize server %q: %v", cfg.Name, err)
			_ = client.Close()
			delete(m.clients, cfg.Name)
			continue
		}

		// ツール一覧を取得
		tools, err := client.ListTools(ctx)
		if err != nil {
			log.Printf("[mcp] WARNING: failed to list tools from server %q: %v", cfg.Name, err)
			_ = client.Close()
			delete(m.clients, cfg.Name)
			continue
		}

		// サーバー名を各ツールに設定
		for i := range tools {
			tools[i].Server = cfg.Name
		}
		m.tools[cfg.Name] = tools
	}

	return nil
}

// ListAllTools は全サーバーのツールを集約して返す
func (m *MCPManager) ListAllTools() []ToolSchema {
	var all []ToolSchema
	for _, tools := range m.tools {
		all = append(all, tools...)
	}
	return all
}

// CallTool は指定されたサーバーのツールを呼び出す
func (m *MCPManager) CallTool(ctx context.Context, server, tool string, args map[string]any) (*CallResult, error) {
	client, ok := m.clients[server]
	if !ok {
		return nil, fmt.Errorf("mcp: unknown server %q", server)
	}
	return client.CallTool(ctx, tool, args)
}

// IsProposalRequired は指定サーバーがユーザー承認を要求するかどうかを返す。
// デフォルトは false。
func (m *MCPManager) IsProposalRequired(server string) bool {
	for _, cfg := range m.configs {
		if cfg.Name == server {
			if cfg.ProposalRequired != nil {
				return *cfg.ProposalRequired
			}
			return false
		}
	}
	return false
}

// Close は全 MCP サーバーのプロセスを終了させる
func (m *MCPManager) Close() error {
	var lastErr error
	for name, client := range m.clients {
		if err := client.Close(); err != nil {
			log.Printf("[mcp] WARNING: failed to close server %q: %v", name, err)
			lastErr = err
		}
		delete(m.clients, name)
	}
	return lastErr
}
