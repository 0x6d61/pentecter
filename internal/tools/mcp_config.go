package tools

import (
	"os"

	"gopkg.in/yaml.v3"
)

// MCPTransport は MCP サーバーへの接続方式。
type MCPTransport string

const (
	MCPTransportHTTP  MCPTransport = "http"  // HTTP SSE（リモート/ローカル）
	MCPTransportStdio MCPTransport = "stdio" // stdio（ローカルプロセス）
)

// MCPServerDef は MCP サーバーの接続設定。
type MCPServerDef struct {
	// Tool はこのサーバーが担当するツール名（Registry での解決キー）。
	Tool string `yaml:"tool"`
	// Transport は接続方式。
	Transport MCPTransport `yaml:"transport"`
	// URL は HTTP SSE エンドポイント（transport: http の場合）。
	URL string `yaml:"url"`
	// Command は stdio サーバーの起動コマンド（transport: stdio の場合）。
	Command string `yaml:"command"`
	// Args は stdio サーバーの起動引数。
	Args []string `yaml:"args"`
	// Headers は HTTP リクエストに付加するヘッダー（認証等）。
	// 値に ${ENV_VAR} 形式を含む場合は環境変数に展開される。
	Headers map[string]string `yaml:"headers"`
}

// MCPConfig は mcp-servers.yaml の全体構造。
type MCPConfig struct {
	Servers []MCPServerDef `yaml:"servers"`
}

// LoadMCPConfigFile は YAML ファイルから MCPConfig を読み込む。
func LoadMCPConfigFile(path string) (*MCPConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg MCPConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	// Headers の環境変数を展開
	for i, srv := range cfg.Servers {
		for k, v := range srv.Headers {
			cfg.Servers[i].Headers[k] = os.ExpandEnv(v)
		}
	}
	return &cfg, nil
}
