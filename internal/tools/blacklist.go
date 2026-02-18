package tools

import "regexp"

// Blacklist はホスト実行コマンドの危険パターンを保持する。
// Docker 実行にはチェックを省略する（隔離済みのため）。
type Blacklist struct {
	patterns []*regexp.Regexp
}

// NewBlacklist は patterns をコンパイルして Blacklist を返す。
// 不正な正規表現はパニックではなくスキップする。
func NewBlacklist(patterns []string) *Blacklist {
	bl := &Blacklist{}
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			continue // 不正なパターンは無視
		}
		bl.patterns = append(bl.patterns, re)
	}
	return bl
}

// Match は command がブラックリストのいずれかに一致するか検査する。
func (b *Blacklist) Match(command string) bool {
	for _, re := range b.patterns {
		if re.MatchString(command) {
			return true
		}
	}
	return false
}
