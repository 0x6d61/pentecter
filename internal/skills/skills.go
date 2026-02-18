// Package skills はペンテスト手順テンプレート（スキル）を管理する。
//
// スキルは Markdown + YAML frontmatter 形式で定義する:
//
//	---
//	name: web-recon
//	description: Webアプリ初期偵察
//	---
//
//	Perform web application reconnaissance...
//
// ユーザーが "/web-recon" と入力するとスキルのプロンプトが Brain のコンテキストに追加される。
package skills

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Skill はペンテスト手順テンプレートを定義する。
type Skill struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	// Prompt は Brain に追加注入するプロンプトテキスト（Markdown 本文）。
	Prompt string
}

// Registry はロード済みスキルを管理する。
type Registry struct {
	skills map[string]*Skill // key: skill name（スラッシュなし）
}

// NewRegistry は空の Registry を返す。
func NewRegistry() *Registry {
	return &Registry{skills: make(map[string]*Skill)}
}

// LoadDir は dir 以下の *.md ファイルをロードする（*.yaml も後方互換で対応）。
// ディレクトリが存在しなくてもエラーにはしない。
func (r *Registry) LoadDir(dir string) error {
	return filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}

		switch {
		case strings.HasSuffix(path, ".md"):
			if sk := parseMDSkill(path); sk != nil {
				r.skills[sk.Name] = sk
			}
		case strings.HasSuffix(path, ".yaml"):
			if sk := parseYAMLSkill(path); sk != nil {
				r.skills[sk.Name] = sk
			}
		}
		return nil
	})
}

// parseMDSkill は Markdown + frontmatter 形式のスキルファイルをパースする。
func parseMDSkill(path string) *Skill {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	content := string(data)

	// frontmatter を分離（--- で囲まれた YAML 部分）
	if !strings.HasPrefix(content, "---") {
		return nil
	}
	parts := strings.SplitN(content, "---", 3)
	if len(parts) < 3 {
		return nil
	}

	var sk Skill
	if err := yaml.Unmarshal([]byte(parts[1]), &sk); err != nil || sk.Name == "" {
		return nil
	}
	sk.Prompt = strings.TrimSpace(parts[2])
	return &sk
}

// parseYAMLSkill は後方互換のために YAML 形式もサポートする。
func parseYAMLSkill(path string) *Skill {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	// YAML の prompt フィールドを含む旧形式
	var raw struct {
		Name        string `yaml:"name"`
		Description string `yaml:"description"`
		Prompt      string `yaml:"prompt"`
	}
	if err := yaml.Unmarshal(data, &raw); err != nil || raw.Name == "" {
		return nil
	}
	return &Skill{Name: raw.Name, Description: raw.Description, Prompt: raw.Prompt}
}


// Get はスキル名でスキルを検索する。
func (r *Registry) Get(name string) (*Skill, bool) {
	sk, ok := r.skills[strings.TrimPrefix(name, "/")]
	return sk, ok
}

// Expand はユーザー入力を検査し、スキル呼び出し（/skill-name）なら
// スキルのプロンプトを返す。通常の入力はそのまま返す。
func (r *Registry) Expand(input string) string {
	input = strings.TrimSpace(input)
	if !strings.HasPrefix(input, "/") {
		return input
	}
	name := strings.TrimPrefix(input, "/")
	// スペースで区切られた追加引数は無視（将来の拡張用）
	name = strings.Fields(name)[0]

	if sk, ok := r.skills[name]; ok {
		return strings.TrimSpace(sk.Prompt)
	}
	// 未知のスラッシュコマンドはそのまま返す
	return input
}

// All は登録済みの全スキルを返す。
func (r *Registry) All() []*Skill {
	result := make([]*Skill, 0, len(r.skills))
	for _, sk := range r.skills {
		result = append(result, sk)
	}
	return result
}
