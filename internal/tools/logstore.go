package tools

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// LogStore はツール実行の生出力をメモリに保持する。
// Agent が「nmapのフルログを見せて」と要求したときに参照される。
type LogStore struct {
	mu      sync.RWMutex
	results map[string]*ToolResult // key: ToolResult.ID
}

// NewLogStore は空の LogStore を返す。
func NewLogStore() *LogStore {
	return &LogStore{results: make(map[string]*ToolResult)}
}

// Save はToolResultを保存する。
func (s *LogStore) Save(r *ToolResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.results[r.ID] = r
}

// Get はIDでToolResultを取得する。
func (s *LogStore) Get(id string) (*ToolResult, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.results[id]
	return r, ok
}

// ForTarget はターゲットIPに関連する全ToolResultを新しい順で返す。
func (s *LogStore) ForTarget(target string) []*ToolResult {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var results []*ToolResult
	for _, r := range s.results {
		if r.Target == target {
			results = append(results, r)
		}
	}
	// 開始時刻で降順ソート（新しい順）
	for i := 0; i < len(results)-1; i++ {
		for j := i + 1; j < len(results); j++ {
			if results[j].StartedAt.After(results[i].StartedAt) {
				results[i], results[j] = results[j], results[i]
			}
		}
	}
	return results
}

// FullText は指定IDのToolResultの生出力全文を文字列で返す。
// Brain が「全ログを見せて」と要求したときに使う。
func (s *LogStore) FullText(id string) (string, bool) {
	r, ok := s.Get(id)
	if !ok {
		return "", false
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("=== %s on %s (ID: %s) ===\n", r.ToolName, r.Target, r.ID))
	for _, line := range r.RawLines {
		sb.WriteString(line.Content)
		sb.WriteByte('\n')
	}
	return sb.String(), true
}

// MakeID はツール名・ターゲット・実行時刻から一意IDを生成する。
func MakeID(toolName, target string, t time.Time) string {
	return fmt.Sprintf("%s@%s@%d", toolName, target, t.UnixMicro())
}
