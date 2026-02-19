package tools_test

import (
	"strings"
	"testing"
	"time"

	"github.com/0x6d61/pentecter/internal/tools"
)

// --- LogStore.Get テスト ---

func TestLogStore_Get_Found(t *testing.T) {
	store := tools.NewLogStore()

	r := &tools.ToolResult{
		ID:        "nmap@10.0.0.5@1706000000",
		ToolName:  "nmap",
		Target:    "10.0.0.5",
		Args:      []string{"-sV", "10.0.0.5"},
		ExitCode:  0,
		StartedAt: time.Now(),
	}
	store.Save(r)

	got, ok := store.Get("nmap@10.0.0.5@1706000000")
	if !ok {
		t.Fatal("Get should find saved result")
	}
	if got.ID != r.ID {
		t.Errorf("Get().ID: got %q, want %q", got.ID, r.ID)
	}
	if got.ToolName != "nmap" {
		t.Errorf("Get().ToolName: got %q, want %q", got.ToolName, "nmap")
	}
	if got.Target != "10.0.0.5" {
		t.Errorf("Get().Target: got %q, want %q", got.Target, "10.0.0.5")
	}
}

func TestLogStore_Get_NotFound(t *testing.T) {
	store := tools.NewLogStore()

	_, ok := store.Get("nonexistent-id")
	if ok {
		t.Error("Get should return false for nonexistent ID")
	}
}

// --- LogStore.ForTarget テスト ---

func TestLogStore_ForTarget(t *testing.T) {
	store := tools.NewLogStore()

	now := time.Now()

	// ターゲット A に 2 つの結果
	store.Save(&tools.ToolResult{
		ID:        "nmap@A@1",
		ToolName:  "nmap",
		Target:    "10.0.0.1",
		StartedAt: now.Add(-2 * time.Minute), // 古い
	})
	store.Save(&tools.ToolResult{
		ID:        "nikto@A@2",
		ToolName:  "nikto",
		Target:    "10.0.0.1",
		StartedAt: now.Add(-1 * time.Minute), // 新しい
	})

	// ターゲット B に 1 つの結果
	store.Save(&tools.ToolResult{
		ID:        "nmap@B@1",
		ToolName:  "nmap",
		Target:    "10.0.0.2",
		StartedAt: now,
	})

	// ターゲット A のみ取得
	results := store.ForTarget("10.0.0.1")
	if len(results) != 2 {
		t.Fatalf("ForTarget(10.0.0.1): got %d results, want 2", len(results))
	}

	// 降順ソート（新しい順）の確認
	if results[0].ToolName != "nikto" {
		t.Errorf("ForTarget[0] should be newest (nikto), got %q", results[0].ToolName)
	}
	if results[1].ToolName != "nmap" {
		t.Errorf("ForTarget[1] should be oldest (nmap), got %q", results[1].ToolName)
	}

	// ターゲット B の結果
	resultsB := store.ForTarget("10.0.0.2")
	if len(resultsB) != 1 {
		t.Fatalf("ForTarget(10.0.0.2): got %d results, want 1", len(resultsB))
	}

	// 存在しないターゲット
	resultsC := store.ForTarget("10.0.0.99")
	if len(resultsC) != 0 {
		t.Errorf("ForTarget(nonexistent): got %d results, want 0", len(resultsC))
	}
}

// --- LogStore.FullText テスト ---

func TestLogStore_FullText(t *testing.T) {
	store := tools.NewLogStore()

	now := time.Now()
	r := &tools.ToolResult{
		ID:       "nmap@10.0.0.5@full",
		ToolName: "nmap",
		Target:   "10.0.0.5",
		RawLines: []tools.OutputLine{
			{Time: now, Content: "Starting Nmap 7.93"},
			{Time: now, Content: "PORT   STATE SERVICE"},
			{Time: now, Content: "22/tcp open  ssh"},
			{Time: now, Content: "80/tcp open  http"},
		},
		StartedAt: now,
	}
	store.Save(r)

	text, ok := store.FullText("nmap@10.0.0.5@full")
	if !ok {
		t.Fatal("FullText should return true for existing result")
	}

	// ヘッダー行の確認
	if !strings.Contains(text, "nmap") {
		t.Errorf("FullText should contain tool name, got:\n%s", text)
	}
	if !strings.Contains(text, "10.0.0.5") {
		t.Errorf("FullText should contain target, got:\n%s", text)
	}

	// 各行が含まれているか
	for _, line := range r.RawLines {
		if !strings.Contains(text, line.Content) {
			t.Errorf("FullText should contain %q, got:\n%s", line.Content, text)
		}
	}
}

func TestLogStore_FullText_NotFound(t *testing.T) {
	store := tools.NewLogStore()

	_, ok := store.FullText("nonexistent-id")
	if ok {
		t.Error("FullText should return false for nonexistent ID")
	}
}

// --- MakeID テスト ---

func TestMakeID(t *testing.T) {
	ts := time.Date(2024, 1, 23, 12, 0, 0, 0, time.UTC)
	id := tools.MakeID("nmap", "10.0.0.5", ts)

	if !strings.HasPrefix(id, "nmap@") {
		t.Errorf("MakeID should start with tool name: got %q", id)
	}
	if !strings.Contains(id, "10.0.0.5") {
		t.Errorf("MakeID should contain target: got %q", id)
	}

	// フォーマット: toolName@target@unixMicro
	parts := strings.Split(id, "@")
	if len(parts) != 3 {
		t.Fatalf("MakeID should produce 3 parts separated by @, got %d: %q", len(parts), id)
	}
	if parts[0] != "nmap" {
		t.Errorf("MakeID parts[0]: got %q, want %q", parts[0], "nmap")
	}
	if parts[1] != "10.0.0.5" {
		t.Errorf("MakeID parts[1]: got %q, want %q", parts[1], "10.0.0.5")
	}
}

func TestMakeID_Uniqueness(t *testing.T) {
	ts1 := time.Date(2024, 1, 23, 12, 0, 0, 0, time.UTC)
	ts2 := time.Date(2024, 1, 23, 12, 0, 1, 0, time.UTC) // 1秒後

	id1 := tools.MakeID("nmap", "10.0.0.5", ts1)
	id2 := tools.MakeID("nmap", "10.0.0.5", ts2)

	if id1 == id2 {
		t.Errorf("MakeID should produce unique IDs for different times: %q == %q", id1, id2)
	}
}
