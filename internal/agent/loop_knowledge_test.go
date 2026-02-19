package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0x6d61/pentecter/internal/knowledge"
	"github.com/0x6d61/pentecter/pkg/schema"
)

// setupKnowledgeTestData はテスト用のナレッジベースディレクトリを作成する
func setupKnowledgeTestData(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	// pentesting-web/sql-injection/README.md
	sqlDir := filepath.Join(dir, "pentesting-web", "sql-injection")
	if err := os.MkdirAll(sqlDir, 0755); err != nil {
		t.Fatal(err)
	}
	sqlContent := `# SQL Injection
## Basic SQL Injection
SELECT * FROM users WHERE id='1' OR '1'='1'
## Union Based
UNION SELECT 1,2,3,username,password FROM users
## Blind SQL Injection
Use time-based blind injection with SLEEP()
`
	if err := os.WriteFile(filepath.Join(sqlDir, "README.md"), []byte(sqlContent), 0644); err != nil {
		t.Fatal(err)
	}

	// network-services-pentesting/ftp.md
	netDir := filepath.Join(dir, "network-services-pentesting")
	if err := os.MkdirAll(netDir, 0755); err != nil {
		t.Fatal(err)
	}
	ftpContent := `# FTP Pentesting
## Anonymous Login
ftp anonymous@target
## vsftpd 2.3.4 Backdoor
vsftpd 2.3.4 has a backdoor on port 6200
`
	if err := os.WriteFile(filepath.Join(netDir, "ftp.md"), []byte(ftpContent), 0644); err != nil {
		t.Fatal(err)
	}

	return dir
}

func TestHandleSearchKnowledge_Success(t *testing.T) {
	dir := setupKnowledgeTestData(t)
	ks := knowledge.NewStore(dir)
	if ks == nil {
		t.Fatal("expected non-nil knowledge store")
	}

	events := make(chan Event, 64)
	loop := &Loop{
		target:         NewTarget(1, "test"),
		events:         events,
		knowledgeStore: ks,
	}

	action := &schema.Action{
		Action:         schema.ActionSearchKnowledge,
		KnowledgeQuery: "sql injection",
	}

	loop.handleSearchKnowledge(action)

	if loop.lastToolOutput == "" {
		t.Fatal("expected non-empty lastToolOutput")
	}
	if !strings.Contains(loop.lastToolOutput, "sql-injection") {
		t.Errorf("expected output to contain 'sql-injection', got: %s", loop.lastToolOutput)
	}
	if !strings.Contains(loop.lastToolOutput, "Found") {
		t.Errorf("expected output to contain 'Found', got: %s", loop.lastToolOutput)
	}
}

func TestHandleSearchKnowledge_NoResults(t *testing.T) {
	dir := setupKnowledgeTestData(t)
	ks := knowledge.NewStore(dir)

	events := make(chan Event, 64)
	loop := &Loop{
		target:         NewTarget(1, "test"),
		events:         events,
		knowledgeStore: ks,
	}

	action := &schema.Action{
		Action:         schema.ActionSearchKnowledge,
		KnowledgeQuery: "nonexistent_topic_xyz",
	}

	loop.handleSearchKnowledge(action)

	if !strings.Contains(loop.lastToolOutput, "No results found") {
		t.Errorf("expected 'No results found', got: %s", loop.lastToolOutput)
	}
}

func TestHandleSearchKnowledge_NoStore(t *testing.T) {
	events := make(chan Event, 64)
	loop := &Loop{
		target:         NewTarget(1, "test"),
		events:         events,
		knowledgeStore: nil,
	}

	action := &schema.Action{
		Action:         schema.ActionSearchKnowledge,
		KnowledgeQuery: "sql",
	}

	loop.handleSearchKnowledge(action)

	if !strings.Contains(loop.lastToolOutput, "not configured") {
		t.Errorf("expected 'not configured' error, got: %s", loop.lastToolOutput)
	}
}

func TestHandleSearchKnowledge_EmptyQuery(t *testing.T) {
	dir := setupKnowledgeTestData(t)
	ks := knowledge.NewStore(dir)

	events := make(chan Event, 64)
	loop := &Loop{
		target:         NewTarget(1, "test"),
		events:         events,
		knowledgeStore: ks,
	}

	action := &schema.Action{
		Action:         schema.ActionSearchKnowledge,
		KnowledgeQuery: "",
	}

	loop.handleSearchKnowledge(action)

	if !strings.Contains(loop.lastToolOutput, "empty") {
		t.Errorf("expected 'empty' error, got: %s", loop.lastToolOutput)
	}
}

func TestHandleReadKnowledge_Success(t *testing.T) {
	dir := setupKnowledgeTestData(t)
	ks := knowledge.NewStore(dir)

	events := make(chan Event, 64)
	loop := &Loop{
		target:         NewTarget(1, "test"),
		events:         events,
		knowledgeStore: ks,
	}

	action := &schema.Action{
		Action:        schema.ActionReadKnowledge,
		KnowledgePath: "network-services-pentesting/ftp.md",
	}

	loop.handleReadKnowledge(action)

	if !strings.Contains(loop.lastToolOutput, "vsftpd 2.3.4") {
		t.Errorf("expected output to contain 'vsftpd 2.3.4', got: %s", loop.lastToolOutput)
	}
}

func TestHandleReadKnowledge_NotFound(t *testing.T) {
	dir := setupKnowledgeTestData(t)
	ks := knowledge.NewStore(dir)

	events := make(chan Event, 64)
	loop := &Loop{
		target:         NewTarget(1, "test"),
		events:         events,
		knowledgeStore: ks,
	}

	action := &schema.Action{
		Action:        schema.ActionReadKnowledge,
		KnowledgePath: "nonexistent/file.md",
	}

	loop.handleReadKnowledge(action)

	if !strings.Contains(loop.lastToolOutput, "Error") {
		t.Errorf("expected error message, got: %s", loop.lastToolOutput)
	}
}

func TestHandleReadKnowledge_NoStore(t *testing.T) {
	events := make(chan Event, 64)
	loop := &Loop{
		target:         NewTarget(1, "test"),
		events:         events,
		knowledgeStore: nil,
	}

	action := &schema.Action{
		Action:        schema.ActionReadKnowledge,
		KnowledgePath: "some/file.md",
	}

	loop.handleReadKnowledge(action)

	if !strings.Contains(loop.lastToolOutput, "not configured") {
		t.Errorf("expected 'not configured' error, got: %s", loop.lastToolOutput)
	}
}

func TestHandleReadKnowledge_EmptyPath(t *testing.T) {
	dir := setupKnowledgeTestData(t)
	ks := knowledge.NewStore(dir)

	events := make(chan Event, 64)
	loop := &Loop{
		target:         NewTarget(1, "test"),
		events:         events,
		knowledgeStore: ks,
	}

	action := &schema.Action{
		Action:        schema.ActionReadKnowledge,
		KnowledgePath: "",
	}

	loop.handleReadKnowledge(action)

	if !strings.Contains(loop.lastToolOutput, "empty") {
		t.Errorf("expected 'empty' error, got: %s", loop.lastToolOutput)
	}
}
