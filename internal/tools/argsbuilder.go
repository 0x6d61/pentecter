package tools

import (
	"fmt"
	"regexp"
	"strings"
)

// tokenRe は "{key}" または "{key!}"（必須マーカー付き）を検出する。
var tokenRe = regexp.MustCompile(`\{(\w+)(!?)\}`)

// BuildCLIArgs は args_template と map[string]any の args から CLI 引数スライスを生成する。
//
// テンプレートルール:
//   - {key}  : args[key] が存在すれば展開。なければトークングループを除去。
//   - {key!} : args[key] が必須。なければエラー。
//   - string 値: そのまま展開
//   - []any 値:  要素ごとに独立した引数として展開
//   - template が空: args["_args"] の []any をそのまま返す
func BuildCLIArgs(template string, args map[string]any) ([]string, error) {
	// template が空のとき: _args キーの配列をそのまま返す
	if strings.TrimSpace(template) == "" {
		if raw, ok := args["_args"]; ok {
			return toStringSlice(raw)
		}
		return nil, nil
	}

	// テンプレートをスペースで分割し、各トークングループを処理する。
	// "トークングループ" = スペース区切りの 1 つ以上の連続した単語。
	// 例: "-p {ports}" は 2 トークン（"-p" と "{ports}"）で構成されるグループ。
	groups := splitGroups(template)
	var result []string

	for _, group := range groups {
		expanded, skip, err := expandGroup(group, args)
		if err != nil {
			return nil, err
		}
		if !skip {
			result = append(result, expanded...)
		}
	}

	return result, nil
}

// splitGroups はテンプレートを「グループ」に分割する。
// グループとは、{key} を含む連続したトークンのまとまり。
// 例: "-p {ports} {target}" → ["-p {ports}", "{target}"]
// ただし {key} を含まないリテラルトークンは独立したグループとして扱う。
func splitGroups(template string) []string {
	tokens := strings.Fields(template)
	var groups []string
	i := 0
	for i < len(tokens) {
		if tokenRe.MatchString(tokens[i]) {
			// {key} トークン → 直前のリテラルと連結してグループを形成
			if i > 0 && !tokenRe.MatchString(tokens[i-1]) {
				// 直前のリテラルを結合
				groups[len(groups)-1] += " " + tokens[i]
			} else {
				groups = append(groups, tokens[i])
			}
		} else {
			// リテラルトークン
			if i+1 < len(tokens) && tokenRe.MatchString(tokens[i+1]) {
				// 次が {key} → 前置リテラルとして同一グループに
				groups = append(groups, tokens[i]+" "+tokens[i+1])
				i += 2
				continue
			}
			groups = append(groups, tokens[i])
		}
		i++
	}
	return groups
}

// expandGroup はグループ内の {key} を展開する。
// グループ内に {key} が含まれ、かつ key が args にない場合は skip=true を返す。
func expandGroup(group string, args map[string]any) (expanded []string, skip bool, err error) {
	matches := tokenRe.FindAllStringSubmatch(group, -1)
	if len(matches) == 0 {
		// リテラルのみ → そのまま
		return strings.Fields(group), false, nil
	}

	result := group
	for _, m := range matches {
		placeholder := m[0] // e.g., "{target}" or "{target!}"
		key := m[1]
		required := m[2] == "!"

		val, exists := args[key]
		if !exists {
			if required {
				return nil, false, fmt.Errorf("BuildCLIArgs: required key %q missing in args", key)
			}
			// オプションキーが missing → グループごとスキップ
			return nil, true, nil
		}

		strs, err := toStringSlice(val)
		if err != nil {
			return nil, false, fmt.Errorf("BuildCLIArgs: key %q: %w", key, err)
		}

		// {key} をスペース結合した文字列で置換（後でまた分割）
		result = strings.ReplaceAll(result, placeholder, strings.Join(strs, " "))
	}

	return strings.Fields(result), false, nil
}

// toStringSlice は any 値を []string に変換する。
// string → ["value"]
// []any → 各要素を文字列化
func toStringSlice(v any) ([]string, error) {
	switch val := v.(type) {
	case string:
		if val == "" {
			return nil, nil
		}
		return strings.Fields(val), nil
	case []any:
		result := make([]string, 0, len(val))
		for i, elem := range val {
			s, ok := elem.(string)
			if !ok {
				return nil, fmt.Errorf("element[%d] is not a string: %T", i, elem)
			}
			result = append(result, s)
		}
		return result, nil
	case []string:
		return val, nil
	case nil:
		return nil, nil
	default:
		return []string{fmt.Sprintf("%v", v)}, nil
	}
}
