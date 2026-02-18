package tools

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Registry はロード済みツール定義と MCP サーバー設定を管理する。
// 解決優先順位: MCP → YAML subprocess → エラー
type Registry struct {
	defs       map[string]*ToolDef     // YAML 定義
	mcpServers map[string]*MCPExecutor // MCP Executor（ツール名→Executor）
}

// NewRegistry は空の Registry を返す。
func NewRegistry() *Registry {
	return &Registry{
		defs:       make(map[string]*ToolDef),
		mcpServers: make(map[string]*MCPExecutor),
	}
}

// LoadDir は dir 以下の *.yaml ファイル（mcp-servers.yaml を除く）をロードして YAML 定義を登録する。
func (r *Registry) LoadDir(dir string) error {
	return filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() || !strings.HasSuffix(path, ".yaml") {
			return nil
		}
		if filepath.Base(path) == "mcp-servers.yaml" {
			return nil // MCP 設定は LoadMCPConfig で別途ロード
		}
		if loadErr := r.loadFile(path); loadErr != nil {
			return fmt.Errorf("load %s: %w", path, loadErr)
		}
		return nil
	})
}

func (r *Registry) loadFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var def ToolDef
	if err := yaml.Unmarshal(data, &def); err != nil {
		return fmt.Errorf("parse yaml: %w", err)
	}
	if def.Name == "" {
		return fmt.Errorf("tool definition missing 'name' field")
	}
	r.defs[def.Name] = &def
	return nil
}

// LoadMCPConfig は mcp-servers.yaml をロードして MCP Executor を登録する。
// ここでは接続確認は行わない（起動を遅らせないため）。
// 実際の接続は Execute 呼び出し時に行われる。
func (r *Registry) LoadMCPConfig(path string) error {
	cfg, err := LoadMCPConfigFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // ファイルなしは正常（MCP オプション）
		}
		return fmt.Errorf("mcp config: %w", err)
	}
	for _, srv := range cfg.Servers {
		r.mcpServers[srv.Tool] = newMCPExecutor(srv)
	}
	return nil
}

// Register はプログラム的に ToolDef を登録する（テスト・組み込みツール向け）。
func (r *Registry) Register(def *ToolDef) {
	r.defs[def.Name] = def
}

// Resolve はツール名に対応する Executor を返す。
//
// 解決順序:
//  1. MCP サーバーが設定されている → FallbackExecutor（MCP → YAML フォールバック付き）
//  2. YAML 定義のみある → YAMLExecutor
//  3. どちらもない → false
func (r *Registry) Resolve(name string) (Executor, bool) {
	mcp, hasMCP := r.mcpServers[name]
	def, hasYAML := r.defs[name]

	if hasMCP && hasYAML {
		// MCP 優先、失敗時は YAML にフォールバック
		return &FallbackExecutor{primary: mcp, fallback: &YAMLExecutor{def: def}}, true
	}
	if hasMCP {
		return mcp, true
	}
	if hasYAML {
		return &YAMLExecutor{def: def}, true
	}
	return nil, false
}

// FallbackExecutor は primary Executor が失敗したとき fallback に切り替える。
type FallbackExecutor struct {
	primary  Executor
	fallback Executor
}

func (f *FallbackExecutor) ExecutorType() string { return f.primary.ExecutorType() + "+fallback" }

func (f *FallbackExecutor) Execute(ctx context.Context, store *LogStore, args map[string]any) (<-chan OutputLine, <-chan *ToolResult) {
	linesCh := make(chan OutputLine, 256)
	resultCh := make(chan *ToolResult, 1)

	go func() {
		defer close(linesCh)
		defer close(resultCh)

		pLines, pResult := f.primary.Execute(ctx, store, args)
		for l := range pLines {
			select {
			case linesCh <- l:
			case <-ctx.Done():
				return
			}
		}
		res := <-pResult

		if res.Err != nil && f.fallback != nil {
			// primary 失敗 → fallback へ
			fLines, fResult := f.fallback.Execute(ctx, store, args)
			for l := range fLines {
				select {
				case linesCh <- l:
				case <-ctx.Done():
					return
				}
			}
			res = <-fResult
		}

		resultCh <- res
	}()

	return linesCh, resultCh
}

// Get は後方互換のために ToolDef を返す（Runner と互換性のため残す）。
func (r *Registry) Get(name string) (*ToolDef, bool) {
	d, ok := r.defs[name]
	return d, ok
}

// All は登録済みの全 ToolDef を返す。
func (r *Registry) All() []*ToolDef {
	result := make([]*ToolDef, 0, len(r.defs))
	for _, d := range r.defs {
		result = append(result, d)
	}
	return result
}
