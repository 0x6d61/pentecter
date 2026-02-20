// Package agent — loop_knowledge.go は search_knowledge / read_knowledge アクションのハンドラを定義する。
package agent

import (
	"fmt"
	"strings"

	"github.com/0x6d61/pentecter/pkg/schema"
)

const (
	// knowledgeSearchMaxResults は検索結果の最大件数
	knowledgeSearchMaxResults = 10
	// knowledgeReadMaxBytes は読み取りファイルの最大バイト数
	knowledgeReadMaxBytes = 30000
)

// handleSearchKnowledge は knowledge_query でナレッジベースを検索し結果を lastToolOutput に格納する。
func (l *Loop) handleSearchKnowledge(action *schema.Action) {
	if l.knowledgeStore == nil {
		l.lastToolOutput = "Error: Knowledge base not configured. Clone HackTricks: git clone --depth 1 https://github.com/carlospolop/hacktricks.git"
		return
	}

	query := action.KnowledgeQuery
	if query == "" {
		l.lastToolOutput = "Error: knowledge_query is empty"
		return
	}

	l.emit(Event{Type: EventLog, Source: SourceSystem,
		Message: fmt.Sprintf("Searching knowledge base: %q", query)})

	results := l.knowledgeStore.Search(query, knowledgeSearchMaxResults)
	if len(results) == 0 {
		l.lastToolOutput = fmt.Sprintf("No results found for: %q", query)
		return
	}

	// 結果をテキストフォーマットで組み立て
	var sb strings.Builder
	fmt.Fprintf(&sb, "Found %d results for %q:\n\n", len(results), query)
	for i, r := range results {
		fmt.Fprintf(&sb, "[%d] %s\n", i+1, r.File)
		if r.Title != "" {
			fmt.Fprintf(&sb, "    Title: %s\n", r.Title)
		}
		if r.Section != "" {
			fmt.Fprintf(&sb, "    Section: %s\n", r.Section)
		}
		if r.Snippet != "" {
			fmt.Fprintf(&sb, "    Snippet: %s\n", r.Snippet)
		}
		fmt.Fprintf(&sb, "    Matches: %d\n\n", r.MatchCount)
	}
	sb.WriteString("Use read_knowledge with the file path to read full article.")
	l.lastToolOutput = sb.String()
}

// handleReadKnowledge は knowledge_path のファイルを読み取り lastToolOutput に格納する。
func (l *Loop) handleReadKnowledge(action *schema.Action) {
	if l.knowledgeStore == nil {
		l.lastToolOutput = "Error: Knowledge base not configured. Clone HackTricks: git clone --depth 1 https://github.com/carlospolop/hacktricks.git"
		return
	}

	path := action.KnowledgePath
	if path == "" {
		l.lastToolOutput = "Error: knowledge_path is empty"
		return
	}

	l.emit(Event{Type: EventLog, Source: SourceSystem,
		Message: fmt.Sprintf("Reading knowledge article: %s", path)})

	content, err := l.knowledgeStore.ReadFile(path, knowledgeReadMaxBytes)
	if err != nil {
		l.lastToolOutput = fmt.Sprintf("Error reading knowledge file: %v", err)
		return
	}

	l.lastToolOutput = content
}
