package tools

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Registry はロード済みツール定義を管理する。
type Registry struct {
	defs map[string]*ToolDef
}

// NewRegistry は空の Registry を返す。
func NewRegistry() *Registry {
	return &Registry{defs: make(map[string]*ToolDef)}
}

// LoadDir は dir 以下の *.yaml ファイルをすべてロードして登録する。
// ファイルが見つからなくてもエラーにはしない（起動時の柔軟性のため）。
func (r *Registry) LoadDir(dir string) error {
	return filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // ディレクトリが存在しない等は無視
		}
		if d.IsDir() || !strings.HasSuffix(path, ".yaml") {
			return nil
		}
		if loadErr := r.loadFile(path); loadErr != nil {
			return fmt.Errorf("load %s: %w", path, loadErr)
		}
		return nil
	})
}

// loadFile は単一のYAMLファイルを読み込んで登録する。
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

// Register はプログラム的にToolDefを登録する（テスト・組み込みツール向け）。
func (r *Registry) Register(def *ToolDef) {
	r.defs[def.Name] = def
}

// Get は名前でToolDefを取得する。見つからない場合は nil, false。
func (r *Registry) Get(name string) (*ToolDef, bool) {
	d, ok := r.defs[name]
	return d, ok
}

// All は登録済みの全ToolDefを返す。
func (r *Registry) All() []*ToolDef {
	result := make([]*ToolDef, 0, len(r.defs))
	for _, d := range r.defs {
		result = append(result, d)
	}
	return result
}
