package agent

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
)

func TestNewAttackDataTree(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 0, 0)
	if tree.Host != "10.10.11.100" {
		t.Errorf("Host = %q, want %q", tree.Host, "10.10.11.100")
	}
	// デフォルト MaxParallel = 2
	if tree.MaxParallel != 2 {
		t.Errorf("MaxParallel = %d, want 2", tree.MaxParallel)
	}

	tree2 := NewAttackDataTree("10.10.11.100", 4, 0)
	if tree2.MaxParallel != 4 {
		t.Errorf("MaxParallel = %d, want 4", tree2.MaxParallel)
	}
}

func TestAddPort_HTTP(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(80, "http", "Apache 2.4.49")

	if len(tree.Ports) != 1 {
		t.Fatalf("Ports count = %d, want 1", len(tree.Ports))
	}
	node := tree.Ports[0]
	if node.Port != 80 || node.Service != "http" || node.Banner != "Apache 2.4.49" {
		t.Errorf("port node = %d/%s %s", node.Port, node.Service, node.Banner)
	}
	// HTTP ポートは EndpointEnum と VhostDiscov が pending
	if node.EndpointEnum != StatusPending {
		t.Errorf("EndpointEnum = %d, want pending", node.EndpointEnum)
	}
	if node.VhostDiscov != StatusPending {
		t.Errorf("VhostDiscov = %d, want pending", node.VhostDiscov)
	}
}

func TestAddPort_NonHTTP(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(22, "ssh", "OpenSSH 8.2")

	if len(tree.Ports) != 1 {
		t.Fatalf("Ports count = %d, want 1", len(tree.Ports))
	}
	node := tree.Ports[0]
	// 非 HTTP はタスクなし
	if node.EndpointEnum != StatusNone {
		t.Errorf("EndpointEnum = %d, want none", node.EndpointEnum)
	}
	if node.VhostDiscov != StatusNone {
		t.Errorf("VhostDiscov = %d, want none", node.VhostDiscov)
	}
	if node.ParamFuzz != StatusNone {
		t.Errorf("ParamFuzz = %d, want none", node.ParamFuzz)
	}
}

func TestAddEndpoint(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(80, "http", "Apache 2.4.49")
	tree.AddEndpoint("10.10.11.100", 80, "/", "/api")

	node := tree.Ports[0]
	if len(node.Children) != 1 {
		t.Fatalf("Children count = %d, want 1", len(node.Children))
	}
	child := node.Children[0]
	if child.Path != "/api" {
		t.Errorf("Path = %q, want /api", child.Path)
	}
	if child.EndpointEnum != StatusPending {
		t.Errorf("EndpointEnum = %d, want pending", child.EndpointEnum)
	}
	if child.ParamFuzz != StatusPending {
		t.Errorf("ParamFuzz = %d, want pending", child.ParamFuzz)
	}
	if child.ValueFuzz != StatusPending {
		t.Errorf("ValueFuzz = %d, want pending", child.ValueFuzz)
	}
	if child.Profiling != StatusPending {
		t.Errorf("Profiling = %d, want pending", child.Profiling)
	}
}

func TestAddEndpoint_Nested(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(80, "http", "Apache")
	tree.AddEndpoint("10.10.11.100", 80, "/", "/api")
	tree.AddEndpoint("10.10.11.100", 80, "/api", "/api/v1")
	tree.AddEndpoint("10.10.11.100", 80, "/api/v1", "/api/v1/user")

	// / → /api → /api/v1 → /api/v1/user
	api := tree.Ports[0].Children[0]
	if api.Path != "/api" {
		t.Errorf("Path = %q, want /api", api.Path)
	}
	if len(api.Children) != 1 {
		t.Fatalf("api children = %d, want 1", len(api.Children))
	}
	v1 := api.Children[0]
	if v1.Path != "/api/v1" {
		t.Errorf("Path = %q, want /api/v1", v1.Path)
	}
	if len(v1.Children) != 1 {
		t.Fatalf("v1 children = %d, want 1", len(v1.Children))
	}
	user := v1.Children[0]
	if user.Path != "/api/v1/user" {
		t.Errorf("Path = %q, want /api/v1/user", user.Path)
	}
}

func TestAddVhost(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(80, "http", "Apache")
	tree.AddVhost("10.10.11.100", 80, "dev.example.com")

	if len(tree.Vhosts) != 1 {
		t.Fatalf("Vhosts count = %d, want 1", len(tree.Vhosts))
	}
	vhost := tree.Vhosts[0]
	if vhost.Host != "dev.example.com" {
		t.Errorf("Host = %q, want dev.example.com", vhost.Host)
	}
	if vhost.Port != 80 {
		t.Errorf("Port = %d, want 80", vhost.Port)
	}
	if vhost.VhostDiscov != StatusPending {
		t.Errorf("VhostDiscov = %d, want pending", vhost.VhostDiscov)
	}
	if vhost.EndpointEnum != StatusPending {
		t.Errorf("EndpointEnum = %d, want pending", vhost.EndpointEnum)
	}
}

func TestCompleteTask(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(80, "http", "Apache")
	tree.AddEndpoint("10.10.11.100", 80, "/", "/api")

	tree.CompleteTask("10.10.11.100", 80, "/api", TaskEndpointEnum)
	child := tree.Ports[0].Children[0]
	if child.EndpointEnum != StatusComplete {
		t.Errorf("EndpointEnum = %d, want complete", child.EndpointEnum)
	}
	// 他のタスクは変わらない
	if child.ParamFuzz != StatusPending {
		t.Errorf("ParamFuzz = %d, want pending", child.ParamFuzz)
	}
}

func TestHasPending(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	// 空のツリーには pending なし
	if tree.HasPending() {
		t.Error("empty tree should not have pending")
	}

	tree.AddPort(22, "ssh", "OpenSSH")
	// 非 HTTP は pending なし
	if tree.HasPending() {
		t.Error("non-HTTP port should not have pending")
	}

	tree.AddPort(80, "http", "Apache")
	if !tree.HasPending() {
		t.Error("HTTP port should have pending")
	}

	// すべて完了させる
	tree.CompleteTask("10.10.11.100", 80, "", TaskEndpointEnum)
	tree.CompleteTask("10.10.11.100", 80, "", TaskVhostDiscov)
	if tree.HasPending() {
		t.Error("all tasks complete, should not have pending")
	}
}

func TestCountPending(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(80, "http", "Apache")
	// HTTP ポート: EndpointEnum + VhostDiscov = 2 pending
	if got := tree.CountPending(); got != 2 {
		t.Errorf("CountPending = %d, want 2", got)
	}

	tree.AddEndpoint("10.10.11.100", 80, "/", "/api")
	// + EndpointEnum + ParamFuzz + ValueFuzz + Profiling = 6 pending
	if got := tree.CountPending(); got != 6 {
		t.Errorf("CountPending = %d, want 6", got)
	}

	tree.CompleteTask("10.10.11.100", 80, "/api", TaskEndpointEnum)
	if got := tree.CountPending(); got != 5 {
		t.Errorf("CountPending = %d, want 5", got)
	}
}

func TestCountTotal(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(80, "http", "Apache")
	tree.AddPort(22, "ssh", "OpenSSH")
	tree.AddEndpoint("10.10.11.100", 80, "/", "/api")
	// HTTP ポート: 2 tasks + endpoint: 4 tasks (EndpointEnum+ParamFuzz+ValueFuzz+Profiling) = 6
	if got := tree.CountTotal(); got != 6 {
		t.Errorf("CountTotal = %d, want 6", got)
	}
}

func TestNextBatch_RespectsMaxParallel(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(80, "http", "Apache")
	tree.AddEndpoint("10.10.11.100", 80, "/", "/api")
	tree.AddEndpoint("10.10.11.100", 80, "/", "/login")
	tree.AddEndpoint("10.10.11.100", 80, "/", "/admin")

	batch := tree.NextBatch()
	if len(batch) != 2 {
		t.Errorf("NextBatch len = %d, want 2 (max_parallel)", len(batch))
	}

	// active を増やすと batch が減る
	for _, task := range batch {
		tree.StartTask(task)
	}
	batch2 := tree.NextBatch()
	if len(batch2) != 0 {
		t.Errorf("NextBatch len = %d, want 0 (at max_parallel)", len(batch2))
	}
}

func TestNextBatch_Priority(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 10, 0) // 高い max_parallel で全部返す
	tree.AddPort(80, "http", "Apache")
	tree.AddEndpoint("10.10.11.100", 80, "/", "/api")
	tree.AddVhost("10.10.11.100", 80, "dev.example.com")

	batch := tree.NextBatch()
	if len(batch) == 0 {
		t.Fatal("NextBatch returned empty")
	}
	// 最初のタスクは endpoint_enum であるべき（最高優先度）
	if batch[0].Type != TaskEndpointEnum {
		t.Errorf("first task type = %d, want endpoint_enum(%d)", batch[0].Type, TaskEndpointEnum)
	}
}

func TestStartTask_FinishTask(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(80, "http", "Apache")

	batch := tree.NextBatch()
	if len(batch) == 0 {
		t.Fatal("no tasks")
	}
	task := batch[0]
	tree.StartTask(task)

	if tree.active != 1 {
		t.Errorf("active = %d, want 1", tree.active)
	}

	// ノードのステータスが in_progress に
	node := tree.findNode(task.Host, task.Port, task.Path)
	if node == nil {
		t.Fatal("findNode returned nil")
	}
	status := node.getAttackDataStatus(task.Type)
	if status != StatusInProgress {
		t.Errorf("status = %d, want in_progress", status)
	}

	tree.FinishTask(task)
	if tree.active != 0 {
		t.Errorf("active = %d, want 0", tree.active)
	}
	status = node.getAttackDataStatus(task.Type)
	if status != StatusComplete {
		t.Errorf("status = %d, want complete", status)
	}
}

func TestRenderTree(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(22, "ssh", "OpenSSH 8.2")
	tree.AddPort(80, "http", "Apache 2.4.49")
	tree.AddEndpoint("10.10.11.100", 80, "/", "/api")
	tree.AddEndpoint("10.10.11.100", 80, "/", "/login")
	tree.CompleteTask("10.10.11.100", 80, "", TaskEndpointEnum)
	tree.CompleteTask("10.10.11.100", 80, "/login", TaskEndpointEnum)
	tree.CompleteTask("10.10.11.100", 80, "/login", TaskParamFuzz)
	tree.CompleteTask("10.10.11.100", 80, "/login", TaskProfiling)

	output := tree.RenderTree()

	// 基本的な内容が含まれるか確認（新しい詳細表示形式）
	checks := []string{
		"10.10.11.100",
		"22/ssh OpenSSH 8.2",
		"80/http Apache 2.4.49",
		"/api",
		"/login",
		"endpoint_enum: complete",  // /login の endpoint_enum
		"param_fuzz: complete",     // /login の param_fuzz
		"profiling: complete",      // /login の profiling
		"endpoint_enum: pending",   // /api の endpoint_enum
		"param_fuzz: pending",      // /api の param_fuzz
		"Progress:",
	}
	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("RenderTree missing %q\noutput:\n%s", check, output)
		}
	}
}

func TestRenderIntel(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(80, "http", "Apache")
	tree.AddEndpoint("10.10.11.100", 80, "/", "/api")

	output := tree.RenderIntel()

	checks := []string{
		"RECON INTEL",
		"ATTACK SURFACE",
		"80/http",
	}
	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("RenderIntel missing %q\noutput:\n%s", check, output)
		}
	}
}

func TestRenderIntel_Empty(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	output := tree.RenderIntel()
	if output != "" {
		t.Errorf("empty tree should return empty intel, got: %q", output)
	}
}

func TestAttackDataTree_LockedByDefault(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	if !tree.IsLocked() {
		t.Error("new AttackDataTree should be locked by default")
	}
}

func TestAttackDataTree_UnlockManual(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(80, "http", "Apache")
	// ロック中
	if !tree.IsLocked() {
		t.Error("should be locked")
	}
	// 手動解除
	tree.Unlock()
	if tree.IsLocked() {
		t.Error("should be unlocked after Unlock()")
	}
}

func TestAttackDataTree_AutoUnlock_WhenNoPending(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(80, "http", "Apache")
	// pending あり → locked
	if !tree.IsLocked() {
		t.Error("should be locked with pending tasks")
	}
	// 全タスク完了
	tree.CompleteTask("10.10.11.100", 80, "", TaskEndpointEnum)
	tree.CompleteTask("10.10.11.100", 80, "", TaskVhostDiscov)
	// pending 0 → auto unlock
	if tree.IsLocked() {
		t.Error("should be auto-unlocked when no pending tasks")
	}
}

func TestAttackDataTree_StaysLocked_WithPending(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(80, "http", "Apache")
	tree.AddEndpoint("10.10.11.100", 80, "/", "/api")
	// まだ pending がある
	tree.CompleteTask("10.10.11.100", 80, "", TaskEndpointEnum)
	if !tree.IsLocked() {
		t.Error("should still be locked with remaining pending tasks")
	}
}

func TestAddFinding(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(80, "http", "Apache")
	tree.AddEndpoint("10.10.11.100", 80, "/", "/api")

	f := Finding{
		Param:    "id",
		Category: "sqli",
		Evidence: "500 + MySQL syntax error on single quote",
		Severity: "high",
	}
	tree.AddFinding("10.10.11.100", 80, "/api", f)

	node := tree.findNode("10.10.11.100", 80, "/api")
	if node == nil {
		t.Fatal("node not found")
	}
	if len(node.Findings) != 1 {
		t.Fatalf("Findings count = %d, want 1", len(node.Findings))
	}
	got := node.Findings[0]
	if got.Param != "id" {
		t.Errorf("Param = %q, want %q", got.Param, "id")
	}
	if got.Category != "sqli" {
		t.Errorf("Category = %q, want %q", got.Category, "sqli")
	}
	if got.Evidence != "500 + MySQL syntax error on single quote" {
		t.Errorf("Evidence = %q", got.Evidence)
	}
	if got.Severity != "high" {
		t.Errorf("Severity = %q, want %q", got.Severity, "high")
	}
}

func TestAddFinding_MultipleFindings(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(80, "http", "Apache")
	tree.AddEndpoint("10.10.11.100", 80, "/", "/api")

	findings := []Finding{
		{Param: "id", Category: "sqli", Evidence: "500 + MySQL syntax error", Severity: "high"},
		{Param: "name", Category: "xss", Evidence: "reflected <script> in response", Severity: "medium"},
		{Param: "file", Category: "lfi", Evidence: "/etc/passwd content in response", Severity: "high"},
	}
	for _, f := range findings {
		tree.AddFinding("10.10.11.100", 80, "/api", f)
	}

	node := tree.findNode("10.10.11.100", 80, "/api")
	if node == nil {
		t.Fatal("node not found")
	}
	if len(node.Findings) != 3 {
		t.Fatalf("Findings count = %d, want 3", len(node.Findings))
	}
	// 順序が保持されること
	if node.Findings[0].Param != "id" {
		t.Errorf("Findings[0].Param = %q, want %q", node.Findings[0].Param, "id")
	}
	if node.Findings[1].Param != "name" {
		t.Errorf("Findings[1].Param = %q, want %q", node.Findings[1].Param, "name")
	}
	if node.Findings[2].Param != "file" {
		t.Errorf("Findings[2].Param = %q, want %q", node.Findings[2].Param, "file")
	}
}

func TestAddFinding_NonExistentNode(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(80, "http", "Apache")

	// 存在しないパスに追加 — パニックしないこと
	f := Finding{Param: "id", Category: "sqli", Evidence: "error", Severity: "high"}
	tree.AddFinding("10.10.11.100", 80, "/nonexistent", f)

	// ポートノードに finding が追加されていないこと
	node := tree.Ports[0]
	if len(node.Findings) != 0 {
		t.Errorf("Findings count = %d, want 0 (should not add to wrong node)", len(node.Findings))
	}
}

func TestCountFindings(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(80, "http", "Apache")
	tree.AddEndpoint("10.10.11.100", 80, "/", "/api")
	tree.AddEndpoint("10.10.11.100", 80, "/", "/login")

	// 空のツリーは 0
	if got := tree.CountFindings(); got != 0 {
		t.Errorf("CountFindings = %d, want 0", got)
	}

	// /api に2つ追加
	tree.AddFinding("10.10.11.100", 80, "/api", Finding{
		Param: "id", Category: "sqli", Evidence: "error", Severity: "high",
	})
	tree.AddFinding("10.10.11.100", 80, "/api", Finding{
		Param: "name", Category: "xss", Evidence: "reflected", Severity: "medium",
	})
	// /login に1つ追加
	tree.AddFinding("10.10.11.100", 80, "/login", Finding{
		Param: "user", Category: "sqli", Evidence: "blind", Severity: "high",
	})

	if got := tree.CountFindings(); got != 3 {
		t.Errorf("CountFindings = %d, want 3", got)
	}
}

func TestRenderTree_WithFindings(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(80, "http", "Apache")
	tree.AddEndpoint("10.10.11.100", 80, "/", "/api")

	tree.AddFinding("10.10.11.100", 80, "/api", Finding{
		Param:    "id",
		Category: "sqli",
		Evidence: "500 + MySQL syntax error",
		Severity: "high",
	})
	tree.AddFinding("10.10.11.100", 80, "/api", Finding{
		Param:    "name",
		Category: "xss",
		Evidence: "reflected script tag",
		Severity: "medium",
	})

	output := tree.RenderTree()

	// finding 行が含まれること
	checks := []string{
		`finding: param "id"`,
		"sqli",
		"500 + MySQL syntax error",
		`finding: param "name"`,
		"xss",
		"reflected script tag",
	}
	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("RenderTree missing %q\noutput:\n%s", check, output)
		}
	}
}

func TestRenderTree_WithParameters(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(80, "http", "Apache")
	tree.AddEndpointWithStatus("10.10.11.100", 80, "/", "/login", 200)

	tree.AddParameter("10.10.11.100", 80, "/login", "username", "query")
	tree.AddParameter("10.10.11.100", 80, "/login", "password", "query")

	output := tree.RenderTree()

	checks := []string{
		"/login",
		"param: username (query)",
		"param: password (query)",
	}
	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("RenderTree missing %q\noutput:\n%s", check, output)
		}
	}
}

func TestRenderTree_WithParametersAndFindings(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(80, "http", "Apache")
	tree.AddEndpointWithStatus("10.10.11.100", 80, "/", "/api", 200)

	tree.AddParameter("10.10.11.100", 80, "/api", "id", "query")
	tree.AddFinding("10.10.11.100", 80, "/api", Finding{
		Param:    "id",
		Category: "sqli",
		Evidence: "500 + MySQL syntax error",
		Severity: "high",
	})

	output := tree.RenderTree()

	checks := []string{
		"param: id (query)",
		`finding: param "id"`,
		"sqli",
	}
	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("RenderTree missing %q\noutput:\n%s", check, output)
		}
	}

	// param が finding より前に表示されること
	paramIdx := strings.Index(output, "param: id")
	findingIdx := strings.Index(output, "finding:")
	if paramIdx >= findingIdx {
		t.Errorf("param should appear before finding\noutput:\n%s", output)
	}
}

func TestRenderTree_RootParamsAndFindings(t *testing.T) {
	// ポートノードの "/" にパラメータと Finding があるとき
	// renderNode の virtual "/" ノードに正しく渡されること
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(80, "http", "Apache")

	// "/" にパラメータを追加（ポートノード = path ""）
	tree.AddParameter("10.10.11.100", 80, "", "q", "query")
	tree.AddFinding("10.10.11.100", 80, "", Finding{
		Param:    "q",
		Category: "sqli",
		Evidence: "syntax error",
		Severity: "high",
	})

	output := tree.RenderTree()
	t.Logf("RenderTree output:\n%s", output)

	checks := []string{
		"/",
		"param: q (query)",
		`finding: param "q"`,
		"sqli",
	}
	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("RenderTree missing %q\noutput:\n%s", check, output)
		}
	}
}

func TestRenderTree_FullPipeline(t *testing.T) {
	// webfuzz の全モードで検出されたデータが /attackdata で見えること
	tree := NewAttackDataTree("10.10.11.100", 2, 3)
	tree.AddPort(80, "http", "Apache")

	// dir モード: endpoint 検出
	tree.AddEndpointWithStatus("10.10.11.100", 80, "/", "/login", 200)
	tree.AddEndpointWithStatus("10.10.11.100", 80, "/", "/api", 301)
	tree.CompleteTask("10.10.11.100", 80, "", TaskEndpointEnum)

	// param モード: パラメータ検出
	tree.AddParameter("10.10.11.100", 80, "/login", "user", "query")
	tree.AddParameter("10.10.11.100", 80, "/login", "pass", "query")
	tree.CompleteTask("10.10.11.100", 80, "/login", TaskParamFuzz)

	// value モード: finding 検出
	tree.AddFinding("10.10.11.100", 80, "/login", Finding{
		Param:    "user",
		Category: "sqli",
		Evidence: "500 + MySQL syntax error",
		Severity: "high",
	})

	// vhost モード
	tree.AddVhost("10.10.11.100", 80, "dev.example.com")
	tree.CompleteTask("10.10.11.100", 80, "", TaskVhostDiscov)

	output := tree.RenderTree()
	t.Logf("RenderTree output:\n%s", output)

	checks := []string{
		"80/http Apache",
		"vhost_discovery: complete",
		"/login",
		"/api",
		"param: user (query)",
		"param: pass (query)",
		`finding: param "user"`,
		"sqli",
		"[vhost] dev.example.com",
		"endpoint_enum: complete", // port root "/"
	}
	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("RenderTree missing %q\noutput:\n%s", check, output)
		}
	}
}

// --- RenderIntel active タスクカバレッジ ---

func TestRenderTree_WithActiveTasks(t *testing.T) {
	// StartTask で in_progress にした後、RenderTree に "[>]" と "[active]" が含まれること
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(80, "http", "Apache")

	batch := tree.NextBatch()
	if len(batch) == 0 {
		t.Fatal("NextBatch returned empty")
	}
	// タスクを開始 → in_progress
	tree.StartTask(batch[0])

	output := tree.RenderTree()

	// "running" は StatusInProgress の表示（新形式）
	if !strings.Contains(output, "running") {
		t.Errorf("RenderTree should contain 'running' for active task\noutput:\n%s", output)
	}

	// RenderIntel で "HTTPAgent active" が含まれること
	intel := tree.RenderIntel()
	if !strings.Contains(intel, "HTTPAgent active") {
		t.Errorf("RenderIntel should contain 'HTTPAgent active' for in-progress task\noutput:\n%s", intel)
	}
}

// --- renderEndpointNode with findings AND children ---

func TestRenderTree_FindingsAndChildren(t *testing.T) {
	// エンドポイントに finding と子エンドポイントの両方がある場合、
	// ツリーレンダリングで両方が正しく表示されること
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(80, "http", "Apache")
	tree.AddEndpoint("10.10.11.100", 80, "/", "/api")
	// /api の子として /api/v1 を追加
	tree.AddEndpoint("10.10.11.100", 80, "/api", "/api/v1")

	// /api に finding を追加
	tree.AddFinding("10.10.11.100", 80, "/api", Finding{
		Param:    "id",
		Category: "sqli",
		Evidence: "500 error with single quote",
		Severity: "high",
	})

	output := tree.RenderTree()

	// finding が表示されること
	if !strings.Contains(output, `finding: param "id"`) {
		t.Errorf("RenderTree missing finding line\noutput:\n%s", output)
	}
	if !strings.Contains(output, "sqli") {
		t.Errorf("RenderTree missing sqli category\noutput:\n%s", output)
	}

	// 子エンドポイントも表示されること
	if !strings.Contains(output, "/api/v1") {
		t.Errorf("RenderTree missing child endpoint /api/v1\noutput:\n%s", output)
	}

	// ツリーブランチ文字 ("|--" or "+--") が含まれること
	if !strings.Contains(output, "|--") && !strings.Contains(output, "+--") {
		t.Errorf("RenderTree missing tree branch characters\noutput:\n%s", output)
	}
}

// --- findNode for vhost パスのカバレッジ ---

func TestFindNode_Vhost(t *testing.T) {
	// AddVhost で追加した vhost ノードを findNode で見つけられること
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(80, "http", "Apache")
	tree.AddVhost("10.10.11.100", 80, "dev.example.com")

	// CompleteTask は内部で findNode を使う。vhost ノードは host=vhost名
	tree.CompleteTask("dev.example.com", 80, "", TaskEndpointEnum)

	// 確認: vhost ノードの EndpointEnum が complete になっていること
	if len(tree.Vhosts) == 0 {
		t.Fatal("Vhosts should not be empty")
	}
	vnode := tree.Vhosts[0]
	if vnode.EndpointEnum != StatusComplete {
		t.Errorf("vhost EndpointEnum = %d, want complete(%d)", vnode.EndpointEnum, StatusComplete)
	}
}

func TestFindNode_VhostChild(t *testing.T) {
	// vhost に子エンドポイントを追加し、CompleteTask で子の findNode が動作すること
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(80, "http", "Apache")
	tree.AddVhost("10.10.11.100", 80, "dev.example.com")

	// vhost ノードの配下にエンドポイントを追加
	tree.AddEndpoint("dev.example.com", 80, "/", "/admin")

	// 子エンドポイントのタスクを完了 → findNode が vhost 子ノードを辿ること
	tree.CompleteTask("dev.example.com", 80, "/admin", TaskProfiling)

	// 確認: vhost 子ノードの Profiling が complete
	if len(tree.Vhosts) == 0 {
		t.Fatal("Vhosts should not be empty")
	}
	vnode := tree.Vhosts[0]
	if len(vnode.Children) != 1 {
		t.Fatalf("vhost children count = %d, want 1", len(vnode.Children))
	}
	child := vnode.Children[0]
	if child.Path != "/admin" {
		t.Errorf("child path = %q, want /admin", child.Path)
	}
	if child.Profiling != StatusComplete {
		t.Errorf("child Profiling = %d, want complete(%d)", child.Profiling, StatusComplete)
	}
}

// --- CompleteAllPortTasks テスト ---

func TestCompleteAllPortTasks_Basic(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(80, "http", "Apache")

	// SubAgent 単位で active を設定（SpawnWebReconForPort と同等）
	node := tree.Ports[0]
	for _, tt := range []ReconTaskType{TaskEndpointEnum, TaskParamFuzz, TaskProfiling, TaskVhostDiscov} {
		node.setAttackDataStatus(tt, StatusInProgress)
	}
	tree.active = 1 // SubAgent 1つ分

	// CompleteAllPortTasks で全タスクを Complete にする
	tree.CompleteAllPortTasks(80)

	// active が 0 になること（SubAgent 単位で -1）
	if tree.active != 0 {
		t.Errorf("active = %d, want 0 after CompleteAllPortTasks", tree.active)
	}

	// 全タスクが Complete であること
	for _, tt := range []ReconTaskType{TaskEndpointEnum, TaskParamFuzz, TaskProfiling, TaskVhostDiscov} {
		if node.getAttackDataStatus(tt) != StatusComplete {
			t.Errorf("task %v status = %d, want complete", tt, node.getAttackDataStatus(tt))
		}
	}
}

func TestCompleteAllPortTasks_OnlyInProgress(t *testing.T) {
	// InProgress のタスクのみ Complete にし、Pending はスキップすること
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(80, "http", "Apache")

	node := tree.Ports[0]
	// EndpointEnum だけ InProgress にする
	node.setAttackDataStatus(TaskEndpointEnum, StatusInProgress)
	tree.active = 1

	tree.CompleteAllPortTasks(80)

	// active が 0 になること（SubAgent 単位で -1）
	if tree.active != 0 {
		t.Errorf("active = %d, want 0", tree.active)
	}

	// EndpointEnum は Complete
	if node.EndpointEnum != StatusComplete {
		t.Errorf("EndpointEnum = %d, want complete", node.EndpointEnum)
	}

	// VhostDiscov は元の Pending のまま（HTTP ポートは Pending で追加される）
	if node.VhostDiscov != StatusPending {
		t.Errorf("VhostDiscov = %d, want pending (unchanged)", node.VhostDiscov)
	}
}

func TestCompleteAllPortTasks_NoMatchingPort(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(80, "http", "Apache")

	node := tree.Ports[0]
	node.setAttackDataStatus(TaskEndpointEnum, StatusInProgress)
	tree.active = 1

	// 存在しないポートを指定 → 何も変わらない
	tree.CompleteAllPortTasks(443)

	if tree.active != 1 {
		t.Errorf("active = %d, want 1 (no matching port)", tree.active)
	}
	if node.EndpointEnum != StatusInProgress {
		t.Errorf("EndpointEnum = %d, want in_progress (unchanged)", node.EndpointEnum)
	}
}

func TestCompleteAllPortTasks_MultiplePorts(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 4, 0)
	tree.AddPort(80, "http", "Apache")
	tree.AddPort(443, "https", "nginx")

	// 両方を SubAgent 単位で InProgress にする（各1 SubAgent）
	for _, node := range tree.Ports {
		node.setAttackDataStatus(TaskEndpointEnum, StatusInProgress)
	}
	tree.active = 2 // 2 SubAgents

	// port 80 だけ Complete にする
	tree.CompleteAllPortTasks(80)

	// active は 1（port 443 の SubAgent だけ残る）
	if tree.active != 1 {
		t.Errorf("active = %d, want 1", tree.active)
	}

	// port 80 は Complete
	if tree.Ports[0].EndpointEnum != StatusComplete {
		t.Errorf("port 80 EndpointEnum = %d, want complete", tree.Ports[0].EndpointEnum)
	}

	// port 443 は InProgress のまま
	if tree.Ports[1].EndpointEnum != StatusInProgress {
		t.Errorf("port 443 EndpointEnum = %d, want in_progress", tree.Ports[1].EndpointEnum)
	}
}

func TestAddPort_NonHTTPToHTTP_InitializesTasks(t *testing.T) {
	tree := NewAttackDataTree("10.0.0.1", 2, 0)
	// First add as generic TCP
	tree.AddPort(8080, "tcpwrapped", "")
	// Port should not have HTTP tasks
	if tree.Ports[0].EndpointEnum != StatusNone {
		t.Error("non-HTTP port should not have EndpointEnum")
	}
	if tree.Ports[0].VhostDiscov != StatusNone {
		t.Error("non-HTTP port should not have VhostDiscov")
	}
	// Now update to HTTP
	tree.AddPort(8080, "http", "Apache")
	if tree.Ports[0].EndpointEnum != StatusPending {
		t.Error("port updated to HTTP should have EndpointEnum=Pending")
	}
	if tree.Ports[0].VhostDiscov != StatusPending {
		t.Error("port updated to HTTP should have VhostDiscov=Pending")
	}
	// Should still be just one port
	if len(tree.Ports) != 1 {
		t.Errorf("expected 1 port, got %d", len(tree.Ports))
	}
	// Banner should be updated
	if tree.Ports[0].Banner != "Apache" {
		t.Errorf("Banner = %q, want 'Apache'", tree.Ports[0].Banner)
	}
}

func TestAddPort_NonHTTPToHTTP_AlreadyInitialized(t *testing.T) {
	// HTTP ポートとして追加された後、再度 HTTP で更新されても
	// すでに初期化済みのタスクステータスが上書きされないこと
	tree := NewAttackDataTree("10.0.0.1", 2, 0)
	tree.AddPort(80, "http", "Apache")
	// EndpointEnum を InProgress に変更
	tree.Ports[0].EndpointEnum = StatusInProgress
	// 再度 HTTP として追加
	tree.AddPort(80, "http", "Apache 2.4.49")
	// InProgress が StatusPending にリセットされていないこと
	if tree.Ports[0].EndpointEnum != StatusInProgress {
		t.Error("already initialized EndpointEnum should not be reset to Pending")
	}
}

func TestAddPort_Dedup(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(80, "http", "")
	tree.AddPort(80, "http", "Apache 2.4.49")

	if len(tree.Ports) != 1 {
		t.Fatalf("Ports count = %d, want 1 (dedup)", len(tree.Ports))
	}
	// 2回目の banner で更新されている
	if tree.Ports[0].Banner != "Apache 2.4.49" {
		t.Errorf("Banner = %q, want 'Apache 2.4.49'", tree.Ports[0].Banner)
	}
}

func TestAddPort_Dedup_KeepLongerBanner(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(80, "http", "Apache httpd 2.4.49 ((Unix))")
	tree.AddPort(80, "http", "Apache")

	// 短い banner では上書きされない
	if tree.Ports[0].Banner != "Apache httpd 2.4.49 ((Unix))" {
		t.Errorf("Banner = %q, want original longer banner", tree.Ports[0].Banner)
	}
}

func TestAttackDataTree_ConcurrentAccess(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 4, 0)
	var wg sync.WaitGroup

	// 並行で AddPort
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			tree.AddPort(port, "http", "Apache")
		}(8000 + i)
	}

	// 並行で AddEndpoint
	tree.AddPort(80, "http", "Apache")
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			tree.AddEndpoint("10.10.11.100", 80, "/", "/path-"+string(rune('a'+idx)))
		}(i)
	}

	// 並行で Read 系
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = tree.RenderTree()
			_ = tree.CountPending()
			_ = tree.CountComplete()
			_ = tree.CountTotal()
			_ = tree.CountFindings()
			_ = tree.HasPending()
			_ = tree.IsLocked()
			_ = tree.PortCount()
		}()
	}

	wg.Wait()

	// パニックせずに完了すれば OK（-race で検証）
	if tree.PortCount() == 0 {
		t.Error("expected ports to be added")
	}
}

func TestRenderIntel_WithActiveAgents(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(80, "http", "Apache")
	// Simulate HTTPAgent active
	batch := tree.NextBatch()
	if len(batch) > 0 {
		tree.StartTask(batch[0])
	}
	output := tree.RenderIntel()
	if !strings.Contains(output, "RECON INTEL") {
		t.Errorf("should contain RECON INTEL header\noutput:\n%s", output)
	}
	if !strings.Contains(output, "HTTPAgent active on ports: 80") {
		t.Errorf("should show HTTPAgent active on port 80\noutput:\n%s", output)
	}
	if !strings.Contains(output, "ATTACK SURFACE") {
		t.Errorf("should contain ATTACK SURFACE section\noutput:\n%s", output)
	}
}

func TestRenderIntel_WithFindings(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(80, "http", "Apache")
	tree.AddEndpoint("10.10.11.100", 80, "/", "/login")
	tree.AddFinding("10.10.11.100", 80, "/login", Finding{
		Param:    "user",
		Category: "sqli",
		Evidence: "500 + MySQL syntax error",
		Severity: "high",
	})
	output := tree.RenderIntel()
	if !strings.Contains(output, "FINDINGS") {
		t.Errorf("should contain FINDINGS section\noutput:\n%s", output)
	}
	if !strings.Contains(output, "sqli") {
		t.Errorf("should contain sqli finding\noutput:\n%s", output)
	}
}

func TestRenderIntel_AttackSurface(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(22, "ssh", "OpenSSH 8.2")
	tree.AddPort(80, "http", "Apache")
	output := tree.RenderIntel()
	if !strings.Contains(output, "22/ssh") {
		t.Errorf("should list ssh port\noutput:\n%s", output)
	}
	if !strings.Contains(output, "80/http") {
		t.Errorf("should list http port\noutput:\n%s", output)
	}
	if !strings.Contains(output, "not tested") {
		// ssh should show "not tested"
		t.Errorf("ssh should show 'not tested'\noutput:\n%s", output)
	}
}

func TestRenderIntel_ChildPendingPreventsReconComplete(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(80, "http", "Apache")
	// ポートレベルのタスクを complete にする
	tree.CompleteTask("10.10.11.100", 80, "/", TaskEndpointEnum)
	tree.CompleteTask("10.10.11.100", 80, "/", TaskVhostDiscov)
	// 子エンドポイントを追加（ParamFuzz + ValueFuzz + Profiling + EndpointEnum が Pending）
	tree.AddEndpoint("10.10.11.100", 80, "/", "/admin")

	output := tree.RenderIntel()
	// 子に pending タスクがあるのでまだ "recon complete" にならない
	if strings.Contains(output, "recon complete") {
		t.Errorf("should NOT show 'recon complete' when child has pending tasks\noutput:\n%s", output)
	}
	// New format: "recon: N/M tasks" instead of "recon pending"
	// Port has 2 complete + /admin has 4 tasks (EndpointEnum+ParamFuzz+ValueFuzz+Profiling) = 2/6
	if !strings.Contains(output, "2/6") {
		t.Errorf("should show task count 2/6 when child has pending tasks\noutput:\n%s", output)
	}
}

func TestSetChecklist(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(22, "ssh", "OpenSSH 8.2")

	cl := GenerateChecklist("ssh", "OpenSSH 8.2", false)
	tree.SetChecklist(22, cl)

	// Checklist should be set
	node := tree.Ports[0]
	if node.Checklist == nil {
		t.Fatal("Checklist should be set on port 22")
	}
	if len(node.Checklist.Items) == 0 {
		t.Error("Checklist should have items")
	}
}

func TestSetChecklist_NoOpIfAlreadySet(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(22, "ssh", "OpenSSH 8.2")

	cl1 := GenerateChecklist("ssh", "OpenSSH 8.2", false)
	tree.SetChecklist(22, cl1)

	cl2 := GenerateChecklist("ssh", "OpenSSH 8.2", true) // different checklist
	tree.SetChecklist(22, cl2)

	// Should still have the first checklist (no-op on second set)
	node := tree.Ports[0]
	// cl1 has no search-knowledge, cl2 does. If no-op, should NOT have search-knowledge.
	hasKnowledge := false
	for _, item := range node.Checklist.Items {
		if item.ID == "search-knowledge" {
			hasKnowledge = true
		}
	}
	if hasKnowledge {
		t.Error("SetChecklist should be no-op if already set")
	}
}

func TestSetChecklist_SkipsHTTPPorts(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(80, "http", "Apache")

	cl := GenerateChecklist("http", "", false)
	tree.SetChecklist(80, cl)

	// HTTP ports should not get a checklist
	node := tree.Ports[0]
	if node.Checklist != nil {
		t.Error("HTTP port should not get a checklist")
	}
}

func TestSetChecklist_PortNotFound(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(22, "ssh", "OpenSSH 8.2")

	cl := GenerateChecklist("ssh", "OpenSSH 8.2", false)
	// Port 443 doesn't exist - should not panic
	tree.SetChecklist(443, cl)
}

func TestUpdateAllChecklists(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(22, "ssh", "OpenSSH 8.2")
	tree.AddPort(21, "ftp", "vsftpd 2.3.4")

	tree.SetChecklist(22, GenerateChecklist("ssh", "OpenSSH 8.2", false))
	tree.SetChecklist(21, GenerateChecklist("ftp", "vsftpd 2.3.4", false))

	commands := []string{
		"searchsploit ssh OpenSSH 8.2",
		"nmap --script ssh-auth-methods -p22 10.10.11.100",
	}
	tree.UpdateAllChecklists(commands)

	// SSH checklist should have searchsploit and ssh-auth-methods done
	sshNode := tree.Ports[0]
	for _, item := range sshNode.Checklist.Items {
		if item.ID == "searchsploit" && !item.Done {
			t.Error("searchsploit should be done for ssh")
		}
		if item.ID == "ssh-auth-methods" && !item.Done {
			t.Error("ssh-auth-methods should be done")
		}
	}

	// FTP checklist should not be affected (different keywords)
	ftpNode := tree.Ports[1]
	for _, item := range ftpNode.Checklist.Items {
		if item.ID == "searchsploit" && item.Done {
			t.Error("searchsploit should NOT be done for ftp (commands mention ssh, not ftp)")
		}
	}
}

func TestAllChecklistsDone(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(22, "ssh", "OpenSSH 8.2")
	tree.AddPort(80, "http", "Apache") // HTTP port - no checklist

	tree.SetChecklist(22, GenerateChecklist("ssh", "OpenSSH 8.2", false))

	// Not all done yet
	if tree.AllChecklistsDone() {
		t.Error("should not be all done yet")
	}

	// Mark all items done manually
	sshNode := tree.Ports[0]
	for i := range sshNode.Checklist.Items {
		sshNode.Checklist.Items[i].Done = true
	}

	if !tree.AllChecklistsDone() {
		t.Error("should be all done now")
	}
}

func TestAllChecklistsDone_NoChecklists(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(80, "http", "Apache") // HTTP only - no checklists

	// No checklists at all - should return true (vacuously)
	if !tree.AllChecklistsDone() {
		t.Error("no checklists = all done (vacuously true)")
	}
}

func TestRenderIntel_WithChecklist(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(22, "ssh", "OpenSSH 8.2")
	tree.AddPort(80, "http", "Apache")

	tree.SetChecklist(22, GenerateChecklist("ssh", "OpenSSH 8.2", false))

	// Mark searchsploit as done
	commands := []string{"searchsploit ssh OpenSSH 8.2"}
	tree.UpdateAllChecklists(commands)

	output := tree.RenderIntel()

	checks := []string{
		"RECON CHECKLIST",
		"Port 22/ssh",
		"[x] searchsploit",
		"[ ] ", // at least one incomplete item
	}
	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("RenderIntel missing %q\noutput:\n%s", check, output)
		}
	}

	// ATTACK SURFACE should show recon progress
	if !strings.Contains(output, "22/ssh") {
		t.Errorf("ATTACK SURFACE should list ssh port\noutput:\n%s", output)
	}
}

func TestRenderIntel_ChecklistAllComplete(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(22, "ssh", "OpenSSH 8.2")

	tree.SetChecklist(22, GenerateChecklist("ssh", "OpenSSH 8.2", false))

	// Mark all items done
	sshNode := tree.Ports[0]
	for i := range sshNode.Checklist.Items {
		sshNode.Checklist.Items[i].Done = true
	}

	output := tree.RenderIntel()

	if !strings.Contains(output, "ALL ITEMS COMPLETE") {
		t.Errorf("should show ALL ITEMS COMPLETE when all checklist items are done\noutput:\n%s", output)
	}
}

func TestRenderIntel_AllNonHTTPReconComplete(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(22, "ssh", "OpenSSH 8.2")
	tree.AddPort(21, "ftp", "vsftpd 2.3.4")

	tree.SetChecklist(22, GenerateChecklist("ssh", "OpenSSH 8.2", false))
	tree.SetChecklist(21, GenerateChecklist("ftp", "vsftpd 2.3.4", false))

	// Mark all items done
	for _, port := range tree.Ports {
		if port.Checklist != nil {
			for i := range port.Checklist.Items {
				port.Checklist.Items[i].Done = true
			}
		}
	}

	output := tree.RenderIntel()

	if !strings.Contains(output, "ALL NON-HTTP RECON COMPLETE") {
		t.Errorf("should show ALL NON-HTTP RECON COMPLETE\noutput:\n%s", output)
	}
}

func TestRenderIntel_AttackSurface_ChecklistProgress(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(22, "ssh", "OpenSSH 8.2")

	cl := GenerateChecklist("ssh", "OpenSSH 8.2", false)
	tree.SetChecklist(22, cl)

	// Mark 1 item done
	tree.Ports[0].Checklist.Items[0].Done = true

	output := tree.RenderIntel()

	// Should show progress like "recon: 1/3" or "recon: 1/N"
	totalItems := len(tree.Ports[0].Checklist.Items)
	expectedProgress := fmt.Sprintf("recon: 1/%d", totalItems)
	if !strings.Contains(output, expectedProgress) {
		t.Errorf("ATTACK SURFACE should show checklist progress %q\noutput:\n%s", expectedProgress, output)
	}
}

func TestComputeReconProgress_Basic(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(80, "http", "Apache")
	tree.AddEndpoint("10.10.11.100", 80, "/", "/api")
	tree.AddEndpoint("10.10.11.100", 80, "/", "/login")

	// Complete some tasks
	tree.CompleteTask("10.10.11.100", 80, "", TaskEndpointEnum)
	tree.CompleteTask("10.10.11.100", 80, "/api", TaskEndpointEnum)
	tree.CompleteTask("10.10.11.100", 80, "/api", TaskParamFuzz)

	prog := tree.ComputeReconProgress()

	// EndpointEnum: port root(complete) + /api(complete) + /login(pending) = 2/3
	if prog.EndpointEnum.Done != 2 || prog.EndpointEnum.Total != 3 {
		t.Errorf("EndpointEnum = %d/%d, want 2/3", prog.EndpointEnum.Done, prog.EndpointEnum.Total)
	}
	// ParamFuzz: /api(complete) + /login(pending) = 1/2 (port root has no ParamFuzz)
	if prog.ParamFuzz.Done != 1 || prog.ParamFuzz.Total != 2 {
		t.Errorf("ParamFuzz = %d/%d, want 1/2", prog.ParamFuzz.Done, prog.ParamFuzz.Total)
	}
	// ValueFuzz: /api(pending) + /login(pending) = 0/2 (follows ParamFuzz)
	if prog.ValueFuzz.Done != 0 || prog.ValueFuzz.Total != 2 {
		t.Errorf("ValueFuzz = %d/%d, want 0/2", prog.ValueFuzz.Done, prog.ValueFuzz.Total)
	}
	// VhostDiscov: port root has 1 pending = 0/1
	if prog.VhostDiscov.Done != 0 || prog.VhostDiscov.Total != 1 {
		t.Errorf("VhostDiscov = %d/%d, want 0/1", prog.VhostDiscov.Done, prog.VhostDiscov.Total)
	}
}

func TestComputeReconProgress_Empty(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	prog := tree.ComputeReconProgress()

	if prog.EndpointEnum.Total != 0 {
		t.Errorf("empty tree EndpointEnum.Total = %d, want 0", prog.EndpointEnum.Total)
	}
	// PendingPaths is now per TaskProgress, not on ReconProgress
	if len(prog.EndpointEnum.PendingPaths) != 0 {
		t.Errorf("empty tree EndpointEnum.PendingPaths = %v, want empty", prog.EndpointEnum.PendingPaths)
	}
	if len(prog.ParamFuzz.PendingPaths) != 0 {
		t.Errorf("empty tree ParamFuzz.PendingPaths = %v, want empty", prog.ParamFuzz.PendingPaths)
	}
}

func TestComputeReconProgress_PendingPaths(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(80, "http", "Apache")
	tree.AddEndpoint("10.10.11.100", 80, "/", "/api")
	tree.AddEndpoint("10.10.11.100", 80, "/", "/login")
	tree.AddEndpoint("10.10.11.100", 80, "/", "/admin")

	// Complete /api endpoint enum
	tree.CompleteTask("10.10.11.100", 80, "/api", TaskEndpointEnum)

	prog := tree.ComputeReconProgress()

	// EndpointEnum pending paths: / (port root), /login, /admin (but NOT /api since it's complete)
	// Port root path "" should show as "/"
	if len(prog.EndpointEnum.PendingPaths) != 3 {
		t.Errorf("EndpointEnum.PendingPaths = %v, want 3 items", prog.EndpointEnum.PendingPaths)
	}

	// ParamFuzz pending paths: /api, /login, /admin (all 3 have ParamFuzz=Pending)
	if len(prog.ParamFuzz.PendingPaths) != 3 {
		t.Errorf("ParamFuzz.PendingPaths = %v, want 3 items", prog.ParamFuzz.PendingPaths)
	}

	// ValueFuzz pending paths: same as ParamFuzz
	if len(prog.ValueFuzz.PendingPaths) != 3 {
		t.Errorf("ValueFuzz.PendingPaths = %v, want 3 items", prog.ValueFuzz.PendingPaths)
	}
}

func TestComputeReconProgress_MaxPendingPaths(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(80, "http", "Apache")

	// Add 15 endpoints — all pending
	for i := 0; i < 15; i++ {
		path := fmt.Sprintf("/path%d", i)
		tree.AddEndpoint("10.10.11.100", 80, "/", path)
	}

	prog := tree.ComputeReconProgress()

	// Should cap at 10 per task type
	if len(prog.EndpointEnum.PendingPaths) > 10 {
		t.Errorf("EndpointEnum.PendingPaths should be capped at 10, got %d", len(prog.EndpointEnum.PendingPaths))
	}
	if len(prog.ParamFuzz.PendingPaths) > 10 {
		t.Errorf("ParamFuzz.PendingPaths should be capped at 10, got %d", len(prog.ParamFuzz.PendingPaths))
	}
	if len(prog.ValueFuzz.PendingPaths) > 10 {
		t.Errorf("ValueFuzz.PendingPaths should be capped at 10, got %d", len(prog.ValueFuzz.PendingPaths))
	}
	if len(prog.Profiling.PendingPaths) > 10 {
		t.Errorf("Profiling.PendingPaths should be capped at 10, got %d", len(prog.Profiling.PendingPaths))
	}
}

func TestIsReconComplete(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)

	// Empty tree: no tasks = not complete (need at least 1 task)
	if tree.IsReconComplete() {
		t.Error("empty tree should not be complete")
	}

	tree.AddPort(80, "http", "Apache")
	tree.AddPort(22, "ssh", "OpenSSH 8.2")

	// Set checklist for non-HTTP
	tree.SetChecklist(22, GenerateChecklist("ssh", "OpenSSH 8.2", false))

	// Not complete yet
	if tree.IsReconComplete() {
		t.Error("should not be complete with pending tasks")
	}

	// Complete all HTTP tasks
	tree.CompleteTask("10.10.11.100", 80, "", TaskEndpointEnum)
	tree.CompleteTask("10.10.11.100", 80, "", TaskVhostDiscov)

	// Still not complete — checklist not done
	if tree.IsReconComplete() {
		t.Error("should not be complete with checklist incomplete")
	}

	// Complete all checklist items
	sshNode := tree.Ports[1]
	for i := range sshNode.Checklist.Items {
		sshNode.Checklist.Items[i].Done = true
	}

	// Now complete
	if !tree.IsReconComplete() {
		t.Error("should be complete when all HTTP tasks and checklists are done")
	}
}

func TestIsReconComplete_ChecklistIncomplete(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(22, "ssh", "OpenSSH 8.2")
	tree.SetChecklist(22, GenerateChecklist("ssh", "OpenSSH 8.2", false))

	// Checklist incomplete → not complete
	if tree.IsReconComplete() {
		t.Error("should not be complete with incomplete checklist")
	}
}

func TestRenderIntel_ReconProgress(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(80, "http", "Apache")
	tree.AddEndpoint("10.10.11.100", 80, "/", "/api")

	// Complete port-level endpoint enum
	tree.CompleteTask("10.10.11.100", 80, "", TaskEndpointEnum)

	output := tree.RenderIntel()

	checks := []string{
		"RECON PROGRESS",
		"endpoint_enum:",
		"param_fuzz:",
		"value_fuzz:",
		"vhost_discovery:",
	}
	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("RenderIntel missing %q\noutput:\n%s", check, output)
		}
	}
}

func TestRenderIntel_ReconProgressComplete(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(80, "http", "Apache")

	// Complete all port-level tasks
	tree.CompleteTask("10.10.11.100", 80, "", TaskEndpointEnum)
	tree.CompleteTask("10.10.11.100", 80, "", TaskVhostDiscov)

	output := tree.RenderIntel()

	if !strings.Contains(output, "COMPLETE") {
		t.Errorf("should show COMPLETE when all HTTP tasks are done\noutput:\n%s", output)
	}
	// value_fuzz should appear in progress section (port node has no ValueFuzz so it may be 0/0)
	// But the COMPLETE line should still appear
}

func TestRenderIntel_AttackSurface_HTTPTaskCount(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(80, "http", "Apache")
	tree.AddEndpoint("10.10.11.100", 80, "/", "/api")

	// Complete 2 of 6 tasks (EndpointEnum on port + /api)
	// Total: port(EndpointEnum+VhostDiscov) + /api(EndpointEnum+ParamFuzz+ValueFuzz+Profiling) = 6
	tree.CompleteTask("10.10.11.100", 80, "", TaskEndpointEnum)
	tree.CompleteTask("10.10.11.100", 80, "/api", TaskEndpointEnum)

	output := tree.RenderIntel()

	// Should show task count like "recon: 2/6 tasks"
	if !strings.Contains(output, "2/6") {
		t.Errorf("ATTACK SURFACE should show task count 2/6\noutput:\n%s", output)
	}
}

func TestRenderIntel_NoReconProgressForNonHTTPOnly(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(22, "ssh", "OpenSSH 8.2")

	output := tree.RenderIntel()

	// No HTTP ports = no RECON PROGRESS section
	if strings.Contains(output, "RECON PROGRESS") {
		t.Errorf("should NOT show RECON PROGRESS when no HTTP ports\noutput:\n%s", output)
	}
}

func TestSnapshot_Roundtrip(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 3, 0)
	tree.AddPort(80, "http", "Apache 2.4.49")
	tree.AddPort(22, "ssh", "OpenSSH 8.2")
	tree.AddEndpoint("10.10.11.100", 80, "/", "/api")
	tree.AddEndpoint("10.10.11.100", 80, "/api", "/api/v1")
	tree.AddVhost("10.10.11.100", 80, "dev.example.com")
	tree.CompleteTask("10.10.11.100", 80, "", TaskEndpointEnum)

	snap1 := tree.Snapshot()

	// JSON marshal/unmarshal roundtrip
	data, err := json.Marshal(snap1)
	if err != nil {
		t.Fatal(err)
	}
	var snap2 AttackDataSnapshot
	if err := json.Unmarshal(data, &snap2); err != nil {
		t.Fatal(err)
	}

	// Restore from snapshot
	restored := RestoreAttackDataTree(snap2)

	// Verify
	if restored.Host != tree.Host {
		t.Errorf("Host = %q, want %q", restored.Host, tree.Host)
	}
	if restored.MaxParallel != tree.MaxParallel {
		t.Errorf("MaxParallel = %d, want %d", restored.MaxParallel, tree.MaxParallel)
	}
	if len(restored.Ports) != len(tree.Ports) {
		t.Fatalf("Ports count = %d, want %d", len(restored.Ports), len(tree.Ports))
	}
	if len(restored.Vhosts) != len(tree.Vhosts) {
		t.Fatalf("Vhosts count = %d, want %d", len(restored.Vhosts), len(tree.Vhosts))
	}

	// Port 80 should have EndpointEnum=Complete (not reset since it was Complete)
	port80 := restored.Ports[0]
	if port80.EndpointEnum != StatusComplete {
		t.Errorf("port 80 EndpointEnum = %d, want Complete", port80.EndpointEnum)
	}

	// Children preserved
	if len(port80.Children) != 1 {
		t.Fatalf("port 80 children = %d, want 2", len(port80.Children))
	}
	if port80.Children[0].Path != "/api" {
		t.Errorf("child[0].Path = %q, want /api", port80.Children[0].Path)
	}
	// Nested children
	if len(port80.Children[0].Children) != 1 {
		t.Fatalf("/api children = %d, want 1", len(port80.Children[0].Children))
	}
	if port80.Children[0].Children[0].Path != "/api/v1" {
		t.Errorf("nested child path = %q, want /api/v1", port80.Children[0].Children[0].Path)
	}
}

func TestSnapshot_WithChecklist(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(22, "ssh", "OpenSSH 8.2")
	cl := GenerateChecklist("ssh", "OpenSSH 8.2", false)
	tree.SetChecklist(22, cl)
	// Mark one item done
	tree.Ports[0].Checklist.Items[0].Done = true

	snap := tree.Snapshot()
	data, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	var snap2 AttackDataSnapshot
	if err := json.Unmarshal(data, &snap2); err != nil {
		t.Fatal(err)
	}

	restored := RestoreAttackDataTree(snap2)
	sshNode := restored.Ports[0]
	if sshNode.Checklist == nil {
		t.Fatal("Checklist should be preserved")
	}
	if len(sshNode.Checklist.Items) != len(cl.Items) {
		t.Errorf("Checklist items = %d, want %d", len(sshNode.Checklist.Items), len(cl.Items))
	}
	if !sshNode.Checklist.Items[0].Done {
		t.Error("first checklist item should still be Done")
	}
}

func TestSnapshot_WithFindings(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(80, "http", "Apache")
	tree.AddEndpoint("10.10.11.100", 80, "/", "/api")
	tree.AddFinding("10.10.11.100", 80, "/api", Finding{
		Param: "id", Category: "sqli", Evidence: "500 + MySQL syntax error", Severity: "high",
	})
	tree.AddFinding("10.10.11.100", 80, "/api", Finding{
		Param: "name", Category: "xss", Evidence: "reflected <script>", Severity: "medium",
	})

	snap := tree.Snapshot()
	data, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	var snap2 AttackDataSnapshot
	if err := json.Unmarshal(data, &snap2); err != nil {
		t.Fatal(err)
	}

	restored := RestoreAttackDataTree(snap2)
	port80 := restored.Ports[0]
	if len(port80.Children) != 1 {
		t.Fatalf("children count = %d, want 1", len(port80.Children))
	}
	apiNode := port80.Children[0]
	if len(apiNode.Findings) != 2 {
		t.Fatalf("findings count = %d, want 2", len(apiNode.Findings))
	}
	if apiNode.Findings[0].Param != "id" || apiNode.Findings[0].Category != "sqli" {
		t.Errorf("finding[0] = %+v", apiNode.Findings[0])
	}
	if apiNode.Findings[1].Param != "name" || apiNode.Findings[1].Category != "xss" {
		t.Errorf("finding[1] = %+v", apiNode.Findings[1])
	}
}

func TestSnapshot_InProgressResetToPending(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(80, "http", "Apache")
	tree.AddEndpoint("10.10.11.100", 80, "/", "/api")
	// Set tasks to InProgress
	batch := tree.NextBatch()
	for _, task := range batch {
		tree.StartTask(task)
	}
	// Verify InProgress
	port80 := tree.Ports[0]
	if port80.EndpointEnum != StatusInProgress {
		t.Fatalf("should be InProgress, got %d", port80.EndpointEnum)
	}

	snap := tree.Snapshot()
	data, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	var snap2 AttackDataSnapshot
	if err := json.Unmarshal(data, &snap2); err != nil {
		t.Fatal(err)
	}

	restored := RestoreAttackDataTree(snap2)
	// InProgress should be reset to Pending
	restoredPort := restored.Ports[0]
	if restoredPort.EndpointEnum != StatusPending {
		t.Errorf("EndpointEnum should be reset to Pending, got %d", restoredPort.EndpointEnum)
	}
	if restoredPort.VhostDiscov != StatusPending {
		t.Errorf("VhostDiscov should be reset to Pending, got %d", restoredPort.VhostDiscov)
	}
	// Active should be 0
	if restored.Active() != 0 {
		t.Errorf("Active = %d, want 0", restored.Active())
	}
	// Completed tasks should stay Complete
	// (none in this test, but verify StatusNone stays None)
}

func TestPathDepth(t *testing.T) {
	tests := []struct {
		path string
		want int
	}{
		{"/", 0},
		{"", 0},
		{"/api", 1},
		{"/api/v1", 2},
		{"/api/v1/users", 3},
		{"/api/v1/users/details", 4},
		{"/a/b/c/d/e", 5},
	}
	for _, tt := range tests {
		got := pathDepth(tt.path)
		if got != tt.want {
			t.Errorf("pathDepth(%q) = %d, want %d", tt.path, got, tt.want)
		}
	}
}

func TestAddEndpoint_FileExtension_SkipsEndpointEnum(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(80, "http", "Apache")

	// File with extension → EndpointEnum should be StatusNone
	tree.AddEndpoint("10.10.11.100", 80, "/", "/login.php")

	child := tree.Ports[0].Children[0]
	if child.EndpointEnum != StatusNone {
		t.Errorf("EndpointEnum = %d, want StatusNone for file with extension", child.EndpointEnum)
	}
	// ParamFuzz and Profiling should still be Pending
	if child.ParamFuzz != StatusPending {
		t.Errorf("ParamFuzz = %d, want StatusPending", child.ParamFuzz)
	}
	if child.Profiling != StatusPending {
		t.Errorf("Profiling = %d, want StatusPending", child.Profiling)
	}
}

func TestAddEndpoint_FileExtension_Various(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(80, "http", "Apache")

	// Files with extensions → StatusNone for EndpointEnum
	files := []string{"/style.css", "/app.js", "/image.png", "/page.html", "/api.json"}
	for _, f := range files {
		tree.AddEndpoint("10.10.11.100", 80, "/", f)
	}

	for i, child := range tree.Ports[0].Children {
		if child.EndpointEnum != StatusNone {
			t.Errorf("child[%d] %q: EndpointEnum = %d, want StatusNone", i, child.Path, child.EndpointEnum)
		}
	}
}

func TestAddEndpoint_Directory_GetsEndpointEnum(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(80, "http", "Apache")

	// Directory (no extension) → EndpointEnum should be Pending
	tree.AddEndpoint("10.10.11.100", 80, "/", "/api")

	child := tree.Ports[0].Children[0]
	if child.EndpointEnum != StatusPending {
		t.Errorf("EndpointEnum = %d, want StatusPending for directory", child.EndpointEnum)
	}
}

func TestAddEndpoint_MaxDepth_Enforced(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 2) // MaxDepth = 2
	tree.AddPort(80, "http", "Apache")

	// Depth 1: /api → OK (within limit)
	tree.AddEndpoint("10.10.11.100", 80, "/", "/api")
	child := tree.Ports[0].Children[0]
	if child.EndpointEnum != StatusPending {
		t.Errorf("depth 1: EndpointEnum = %d, want Pending", child.EndpointEnum)
	}

	// Depth 2: /api/v1 → OK (at limit)
	tree.AddEndpoint("10.10.11.100", 80, "/api", "/api/v1")
	v1 := child.Children[0]
	if v1.EndpointEnum != StatusPending {
		t.Errorf("depth 2: EndpointEnum = %d, want Pending", v1.EndpointEnum)
	}

	// Depth 3: /api/v1/users → OVER limit → StatusNone
	tree.AddEndpoint("10.10.11.100", 80, "/api/v1", "/api/v1/users")
	users := v1.Children[0]
	if users.EndpointEnum != StatusNone {
		t.Errorf("depth 3: EndpointEnum = %d, want StatusNone (over MaxDepth)", users.EndpointEnum)
	}
	// ParamFuzz/Profiling still Pending
	if users.ParamFuzz != StatusPending {
		t.Errorf("depth 3: ParamFuzz = %d, want Pending", users.ParamFuzz)
	}
}

func TestAddEndpoint_MaxDepth_Default(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0) // 0 → default 3
	if tree.MaxDepth != 3 {
		t.Errorf("MaxDepth = %d, want 3 (default)", tree.MaxDepth)
	}
}

// --- AddEndpointWithStatus テスト ---

func TestAddEndpointWithStatus_200_FullPending(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(80, "http", "Apache")

	tree.AddEndpointWithStatus("10.10.11.100", 80, "/", "/api", 200)

	child := tree.Ports[0].Children[0]
	if child.EndpointEnum != StatusPending {
		t.Errorf("EndpointEnum = %d, want StatusPending for status 200", child.EndpointEnum)
	}
	if child.ParamFuzz != StatusPending {
		t.Errorf("ParamFuzz = %d, want StatusPending for status 200", child.ParamFuzz)
	}
	if child.Profiling != StatusPending {
		t.Errorf("Profiling = %d, want StatusPending for status 200", child.Profiling)
	}
}

func TestAddEndpointWithStatus_403_AllNone(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(80, "http", "Apache")

	tree.AddEndpointWithStatus("10.10.11.100", 80, "/", "/.htaccess", 403)

	child := tree.Ports[0].Children[0]
	if child.EndpointEnum != StatusNone {
		t.Errorf("EndpointEnum = %d, want StatusNone for status 403", child.EndpointEnum)
	}
	if child.ParamFuzz != StatusNone {
		t.Errorf("ParamFuzz = %d, want StatusNone for status 403", child.ParamFuzz)
	}
	if child.Profiling != StatusNone {
		t.Errorf("Profiling = %d, want StatusNone for status 403", child.Profiling)
	}
}

func TestAddEndpointWithStatus_401_AllNone(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(80, "http", "Apache")

	tree.AddEndpointWithStatus("10.10.11.100", 80, "/", "/admin", 401)

	child := tree.Ports[0].Children[0]
	if child.EndpointEnum != StatusNone {
		t.Errorf("EndpointEnum = %d, want StatusNone for status 401", child.EndpointEnum)
	}
	if child.ParamFuzz != StatusNone {
		t.Errorf("ParamFuzz = %d, want StatusNone for status 401", child.ParamFuzz)
	}
	if child.Profiling != StatusNone {
		t.Errorf("Profiling = %d, want StatusNone for status 401", child.Profiling)
	}
}

func TestAddEndpointWithStatus_301_EndpointEnumOnly(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(80, "http", "Apache")

	// 301 redirect typically indicates a directory → EndpointEnum should be Pending
	tree.AddEndpointWithStatus("10.10.11.100", 80, "/", "/api", 301)

	child := tree.Ports[0].Children[0]
	if child.EndpointEnum != StatusPending {
		t.Errorf("EndpointEnum = %d, want StatusPending for status 301 (directory redirect)", child.EndpointEnum)
	}
	if child.ParamFuzz != StatusNone {
		t.Errorf("ParamFuzz = %d, want StatusNone for status 301", child.ParamFuzz)
	}
	if child.Profiling != StatusNone {
		t.Errorf("Profiling = %d, want StatusNone for status 301", child.Profiling)
	}
}

func TestAddEndpointWithStatus_302_EndpointEnumOnly(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(80, "http", "Apache")

	tree.AddEndpointWithStatus("10.10.11.100", 80, "/", "/old-path", 302)

	child := tree.Ports[0].Children[0]
	if child.EndpointEnum != StatusPending {
		t.Errorf("EndpointEnum = %d, want StatusPending for status 302", child.EndpointEnum)
	}
	if child.ParamFuzz != StatusNone {
		t.Errorf("ParamFuzz = %d, want StatusNone for status 302", child.ParamFuzz)
	}
	if child.Profiling != StatusNone {
		t.Errorf("Profiling = %d, want StatusNone for status 302", child.Profiling)
	}
}

func TestAddEndpointWithStatus_0_DefaultBehavior(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(80, "http", "Apache")

	// httpStatus=0 は「不明」→ 従来通り全 Pending（AddEndpoint と同じ動作）
	tree.AddEndpointWithStatus("10.10.11.100", 80, "/", "/api", 0)

	child := tree.Ports[0].Children[0]
	if child.EndpointEnum != StatusPending {
		t.Errorf("EndpointEnum = %d, want StatusPending for httpStatus=0", child.EndpointEnum)
	}
	if child.ParamFuzz != StatusPending {
		t.Errorf("ParamFuzz = %d, want StatusPending for httpStatus=0", child.ParamFuzz)
	}
	if child.Profiling != StatusPending {
		t.Errorf("Profiling = %d, want StatusPending for httpStatus=0", child.Profiling)
	}
}

func TestAddEndpointWithStatus_FileExtension_Overrides(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(80, "http", "Apache")

	// ファイル拡張子あり + status 200 → EndpointEnum=None, ParamFuzz/Profiling=Pending
	tree.AddEndpointWithStatus("10.10.11.100", 80, "/", "/login.php", 200)

	child := tree.Ports[0].Children[0]
	if child.EndpointEnum != StatusNone {
		t.Errorf("EndpointEnum = %d, want StatusNone for file with extension", child.EndpointEnum)
	}
	if child.ParamFuzz != StatusPending {
		t.Errorf("ParamFuzz = %d, want StatusPending for status 200 file", child.ParamFuzz)
	}
	if child.Profiling != StatusPending {
		t.Errorf("Profiling = %d, want StatusPending for status 200 file", child.Profiling)
	}
}

func TestAddEndpointWithStatus_500_AllNone(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(80, "http", "Apache")

	tree.AddEndpointWithStatus("10.10.11.100", 80, "/", "/error", 500)

	child := tree.Ports[0].Children[0]
	if child.EndpointEnum != StatusNone {
		t.Errorf("EndpointEnum = %d, want StatusNone for status 500", child.EndpointEnum)
	}
	if child.ParamFuzz != StatusNone {
		t.Errorf("ParamFuzz = %d, want StatusNone for status 500", child.ParamFuzz)
	}
	if child.Profiling != StatusNone {
		t.Errorf("Profiling = %d, want StatusNone for status 500", child.Profiling)
	}
}

// --- 静的ファイル拡張子 ParamFuzz スキップ テスト ---

func TestAddEndpointWithStatus_StaticFile_SkipsParamFuzz(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(80, "http", "Apache")

	staticFiles := []string{"/style.css", "/app.js", "/logo.png", "/bg.jpg", "/favicon.ico", "/icon.svg", "/font.woff"}
	for _, f := range staticFiles {
		tree.AddEndpointWithStatus("10.10.11.100", 80, "/", f, 200)
	}

	for i, child := range tree.Ports[0].Children {
		if child.ParamFuzz != StatusNone {
			t.Errorf("child[%d] %q: ParamFuzz = %d, want StatusNone (static file)", i, child.Path, child.ParamFuzz)
		}
		if child.Profiling != StatusNone {
			t.Errorf("child[%d] %q: Profiling = %d, want StatusNone (static file)", i, child.Path, child.Profiling)
		}
	}
}

func TestAddEndpointWithStatus_DynamicFile_KeepsParamFuzz(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(80, "http", "Apache")

	// .php, .jsp, .aspx 等は動的ファイル → ParamFuzz=Pending のまま
	dynamicFiles := []string{"/login.php", "/api.jsp", "/admin.aspx", "/search.py"}
	for _, f := range dynamicFiles {
		tree.AddEndpointWithStatus("10.10.11.100", 80, "/", f, 200)
	}

	for i, child := range tree.Ports[0].Children {
		if child.ParamFuzz != StatusPending {
			t.Errorf("child[%d] %q: ParamFuzz = %d, want StatusPending (dynamic file)", i, child.Path, child.ParamFuzz)
		}
	}
}

func TestAddEndpointWithStatus_DirectoryNoExt_KeepsParamFuzz(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(80, "http", "Apache")

	// 拡張子なしディレクトリ → ParamFuzz=Pending
	tree.AddEndpointWithStatus("10.10.11.100", 80, "/", "/api", 200)
	tree.AddEndpointWithStatus("10.10.11.100", 80, "/", "/admin", 200)

	for _, child := range tree.Ports[0].Children {
		if child.ParamFuzz != StatusPending {
			t.Errorf("%q: ParamFuzz = %d, want StatusPending", child.Path, child.ParamFuzz)
		}
	}
}

// --- UI 表示形式テスト ---

func TestRenderEndpointNode_DetailedFormat(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(80, "http", "Apache 2.4.49")
	tree.AddEndpoint("10.10.11.100", 80, "/", "/admin")
	tree.CompleteTask("10.10.11.100", 80, "/admin", TaskEndpointEnum)

	output := tree.RenderTree()

	// 新しい表示形式: 各タスクが独立した行で表示される
	checks := []string{
		"/admin",
		"endpoint_enum: complete",
		"param_fuzz: pending",
		"profiling: pending",
	}
	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("RenderTree missing %q\noutput:\n%s", check, output)
		}
	}
}

func TestRenderEndpointNode_StatusNone_Hidden(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(80, "http", "Apache")
	// status 403 → 全て StatusNone
	tree.AddEndpointWithStatus("10.10.11.100", 80, "/", "/.htaccess", 403)

	output := tree.RenderTree()

	// .htaccess はパス名のみ表示され、タスク行がない
	if !strings.Contains(output, "/.htaccess") {
		t.Errorf("should show .htaccess path\noutput:\n%s", output)
	}
	// .htaccess の直後にタスク行が続かない（StatusNone は非表示）
	lines := strings.Split(output, "\n")
	for i, line := range lines {
		if strings.Contains(line, ".htaccess") {
			// 次の行が endpoint_enum/param_fuzz/profiling ならNG
			if i+1 < len(lines) {
				next := lines[i+1]
				if strings.Contains(next, "endpoint_enum") || strings.Contains(next, "param_fuzz") || strings.Contains(next, "profiling") {
					t.Errorf(".htaccess should not have task lines, next line: %q\noutput:\n%s", next, output)
				}
			}
			break
		}
	}
}

// --- AddEndpoint 重複チェック テスト ---

func TestAddEndpoint_DuplicatePath_NoDuplicate(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(80, "http", "Apache")

	// 同じパスを2回追加
	tree.AddEndpoint("10.10.11.100", 80, "/", "/api")
	tree.AddEndpoint("10.10.11.100", 80, "/", "/api")

	if len(tree.Ports[0].Children) != 1 {
		t.Errorf("Children count = %d, want 1 (no duplicates)", len(tree.Ports[0].Children))
	}
}

func TestAddEndpointWithStatus_DuplicatePath_NoDuplicate(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(80, "http", "Apache")

	// 同じパスを異なるステータスで2回追加 → 1つだけ存在すべき
	tree.AddEndpointWithStatus("10.10.11.100", 80, "/", "/api", 200)
	tree.AddEndpointWithStatus("10.10.11.100", 80, "/", "/api", 301)

	if len(tree.Ports[0].Children) != 1 {
		t.Errorf("Children count = %d, want 1 (no duplicates)", len(tree.Ports[0].Children))
	}
}

func TestAddEndpoint_DuplicateMultiplePaths(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(80, "http", "Apache")

	// 3つの異なるパスを追加、うち /api を2回
	tree.AddEndpoint("10.10.11.100", 80, "/", "/api")
	tree.AddEndpoint("10.10.11.100", 80, "/", "/login")
	tree.AddEndpoint("10.10.11.100", 80, "/", "/api")

	if len(tree.Ports[0].Children) != 2 {
		t.Errorf("Children count = %d, want 2 (/api + /login)", len(tree.Ports[0].Children))
	}
}

// --- "/" 重複防止テスト ---

func TestAddEndpointWithStatus_RootSlash_SkippedOnPortNode(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(80, "http", "Apache")

	// ffuf が "/" を返した場合、ポートノード（path=""）と重複するのでスキップ
	tree.AddEndpointWithStatus("10.10.11.100", 80, "/", "/", 200)

	if len(tree.Ports[0].Children) != 0 {
		t.Errorf("Children count = %d, want 0 (root '/' should not be added as child)", len(tree.Ports[0].Children))
	}
}

func TestAddEndpointWithStatus_TrailingSlash_Normalized(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(80, "http", "Apache")

	// "/controllers/" と "/controllers" は同じとして扱う
	tree.AddEndpointWithStatus("10.10.11.100", 80, "/", "/controllers", 301)
	tree.AddEndpointWithStatus("10.10.11.100", 80, "/", "/controllers/", 301)

	if len(tree.Ports[0].Children) != 1 {
		t.Errorf("Children count = %d, want 1 (trailing slash normalized)", len(tree.Ports[0].Children))
	}
}

// --- ValueFuzz テスト ---

func TestAddEndpointWithStatus_ValueFuzz_FollowsParamFuzz(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(80, "http", "Apache")

	// status 200: ParamFuzz=Pending → ValueFuzz=Pending
	tree.AddEndpointWithStatus("10.10.11.100", 80, "/", "/api", 200)
	child := tree.Ports[0].Children[0]
	if child.ParamFuzz != StatusPending {
		t.Errorf("ParamFuzz = %d, want StatusPending", child.ParamFuzz)
	}
	if child.ValueFuzz != StatusPending {
		t.Errorf("ValueFuzz = %d, want StatusPending (follows ParamFuzz)", child.ValueFuzz)
	}

	// status 301: ParamFuzz=None → ValueFuzz=None
	tree.AddEndpointWithStatus("10.10.11.100", 80, "/", "/redirect", 301)
	redirect := tree.Ports[0].Children[1]
	if redirect.ParamFuzz != StatusNone {
		t.Errorf("redirect ParamFuzz = %d, want StatusNone", redirect.ParamFuzz)
	}
	if redirect.ValueFuzz != StatusNone {
		t.Errorf("redirect ValueFuzz = %d, want StatusNone (follows ParamFuzz)", redirect.ValueFuzz)
	}
}

func TestAddEndpointWithStatus_StaticFile_ValueFuzzNone(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(80, "http", "Apache")

	// Static files skip ParamFuzz/Profiling → ValueFuzz should also be None
	staticFiles := []string{"/style.css", "/app.js", "/logo.png"}
	for _, f := range staticFiles {
		tree.AddEndpointWithStatus("10.10.11.100", 80, "/", f, 200)
	}

	for i, child := range tree.Ports[0].Children {
		if child.ValueFuzz != StatusNone {
			t.Errorf("child[%d] %q: ValueFuzz = %d, want StatusNone (static file)", i, child.Path, child.ValueFuzz)
		}
	}
}

func TestRenderEndpointNode_ValueFuzz_Shown(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(80, "http", "Apache")
	tree.AddEndpointWithStatus("10.10.11.100", 80, "/", "/api", 200)

	output := tree.RenderTree()

	if !strings.Contains(output, "value_fuzz: pending") {
		t.Errorf("RenderTree should show value_fuzz line\noutput:\n%s", output)
	}
}

func TestComputeReconProgress_PendingPathsPerTaskType(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(80, "http", "Apache")
	tree.AddEndpoint("10.10.11.100", 80, "/", "/contact")
	tree.AddEndpoint("10.10.11.100", 80, "/", "/login")
	tree.AddEndpoint("10.10.11.100", 80, "/", "/user")

	// Complete endpoint_enum for all endpoints but NOT param_fuzz/value_fuzz/profiling
	tree.CompleteTask("10.10.11.100", 80, "", TaskEndpointEnum)
	tree.CompleteTask("10.10.11.100", 80, "/contact", TaskEndpointEnum)
	tree.CompleteTask("10.10.11.100", 80, "/login", TaskEndpointEnum)
	tree.CompleteTask("10.10.11.100", 80, "/user", TaskEndpointEnum)

	prog := tree.ComputeReconProgress()

	// endpoint_enum: all complete → no pending paths
	if len(prog.EndpointEnum.PendingPaths) != 0 {
		t.Errorf("EndpointEnum.PendingPaths = %v, want empty (all complete)", prog.EndpointEnum.PendingPaths)
	}

	// param_fuzz: /contact, /login, /user pending (3 items)
	if len(prog.ParamFuzz.PendingPaths) != 3 {
		t.Errorf("ParamFuzz.PendingPaths = %v, want 3 items", prog.ParamFuzz.PendingPaths)
	}

	// value_fuzz: same as param_fuzz
	if len(prog.ValueFuzz.PendingPaths) != 3 {
		t.Errorf("ValueFuzz.PendingPaths = %v, want 3 items", prog.ValueFuzz.PendingPaths)
	}

	// profiling: same
	if len(prog.Profiling.PendingPaths) != 3 {
		t.Errorf("Profiling.PendingPaths = %v, want 3 items", prog.Profiling.PendingPaths)
	}
}

func TestReconProgress_ParamFuzzPendingPaths(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(80, "http", "Apache")
	tree.AddEndpoint("10.10.11.100", 80, "/", "/api")
	tree.AddEndpoint("10.10.11.100", 80, "/", "/login")

	// Complete param_fuzz for /api only
	tree.CompleteTask("10.10.11.100", 80, "/api", TaskParamFuzz)

	prog := tree.ComputeReconProgress()

	// /login still has ParamFuzz=Pending
	if len(prog.ParamFuzz.PendingPaths) != 1 {
		t.Errorf("ParamFuzz.PendingPaths = %v, want 1 item (/login)", prog.ParamFuzz.PendingPaths)
	}
	if len(prog.ParamFuzz.PendingPaths) > 0 && prog.ParamFuzz.PendingPaths[0] != "/login" {
		t.Errorf("ParamFuzz.PendingPaths[0] = %q, want /login", prog.ParamFuzz.PendingPaths[0])
	}
}

func TestSnapshot_ValueFuzz_Roundtrip(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(80, "http", "Apache")
	tree.AddEndpointWithStatus("10.10.11.100", 80, "/", "/api", 200)

	// Complete ValueFuzz on /api
	tree.CompleteTask("10.10.11.100", 80, "/api", TaskValueFuzz)

	snap := tree.Snapshot()
	data, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	var snap2 AttackDataSnapshot
	if err := json.Unmarshal(data, &snap2); err != nil {
		t.Fatal(err)
	}

	restored := RestoreAttackDataTree(snap2)
	apiNode := restored.Ports[0].Children[0]
	if apiNode.ValueFuzz != StatusComplete {
		t.Errorf("ValueFuzz = %d, want StatusComplete after roundtrip", apiNode.ValueFuzz)
	}
	// ParamFuzz should still be Pending (not affected)
	if apiNode.ParamFuzz != StatusPending {
		t.Errorf("ParamFuzz = %d, want StatusPending", apiNode.ParamFuzz)
	}
}

func TestRenderIntel_PendingPathsInline(t *testing.T) {
	tree := NewAttackDataTree("10.10.11.100", 2, 0)
	tree.AddPort(80, "http", "Apache")
	tree.AddEndpoint("10.10.11.100", 80, "/", "/contact")
	tree.AddEndpoint("10.10.11.100", 80, "/", "/login")

	// Complete all endpoint_enum
	tree.CompleteTask("10.10.11.100", 80, "", TaskEndpointEnum)
	tree.CompleteTask("10.10.11.100", 80, "/contact", TaskEndpointEnum)
	tree.CompleteTask("10.10.11.100", 80, "/login", TaskEndpointEnum)

	output := tree.RenderIntel()

	// endpoint_enum should show 100% with no pending inline
	if !strings.Contains(output, "endpoint_enum: 3/3 (100%)") {
		t.Errorf("should show endpoint_enum at 100%%\noutput:\n%s", output)
	}

	// param_fuzz should show pending paths inline
	// Format: "param_fuzz: 0/2 (0%) — pending: /contact, /login"
	if !strings.Contains(output, "pending: /contact") {
		t.Errorf("should show pending paths inline for param_fuzz\noutput:\n%s", output)
	}

	// The old-style separate "Pending:" line should NOT appear
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "Pending:") {
			t.Errorf("should NOT have separate 'Pending:' line\noutput:\n%s", output)
			break
		}
	}
}

// === PortHasPendingChildren tests ===

func TestPortHasPendingChildren_True(t *testing.T) {
	// ポートに Pending 子タスクがある場合 true を返す
	tree := NewAttackDataTree("10.0.0.1", 2, 3)
	tree.AddPort(80, "http", "Apache")
	tree.AddEndpointWithStatus("10.0.0.1", 80, "", "/api", 200)

	// ポートレベルのタスクを Complete にする（SubAgent が MaxTurns で完了した想定）
	node := tree.Ports[0]
	node.SetAttackDataStatusForTest(TaskEndpointEnum, StatusComplete)
	node.SetAttackDataStatusForTest(TaskVhostDiscov, StatusComplete)

	// 子ノードの param_fuzz は Pending のまま
	if !tree.PortHasPendingChildren(80) {
		t.Error("PortHasPendingChildren(80) = false, want true (child has pending tasks)")
	}
}

func TestPortHasPendingChildren_False(t *testing.T) {
	// ポートの子タスクが全て Complete の場合 false を返す
	tree := NewAttackDataTree("10.0.0.1", 2, 3)
	tree.AddPort(80, "http", "Apache")
	tree.AddEndpointWithStatus("10.0.0.1", 80, "", "/api", 200)

	// 全タスクを Complete にする
	node := tree.Ports[0]
	node.SetAttackDataStatusForTest(TaskEndpointEnum, StatusComplete)
	node.SetAttackDataStatusForTest(TaskVhostDiscov, StatusComplete)
	child := node.Children[0]
	child.SetAttackDataStatusForTest(TaskEndpointEnum, StatusComplete)
	child.SetAttackDataStatusForTest(TaskParamFuzz, StatusComplete)
	child.SetAttackDataStatusForTest(TaskValueFuzz, StatusComplete)
	child.SetAttackDataStatusForTest(TaskProfiling, StatusComplete)

	if tree.PortHasPendingChildren(80) {
		t.Error("PortHasPendingChildren(80) = true, want false (all child tasks complete)")
	}
}

func TestPortHasPendingChildren_NoPendingNoChildren(t *testing.T) {
	// 子ノードがないポートは false を返す
	tree := NewAttackDataTree("10.0.0.1", 2, 3)
	tree.AddPort(80, "http", "Apache")

	// ポートレベルのタスクを Complete にする
	node := tree.Ports[0]
	node.SetAttackDataStatusForTest(TaskEndpointEnum, StatusComplete)
	node.SetAttackDataStatusForTest(TaskVhostDiscov, StatusComplete)

	if tree.PortHasPendingChildren(80) {
		t.Error("PortHasPendingChildren(80) = true, want false (no children)")
	}
}

func TestPortHasPendingChildren_DeepNested(t *testing.T) {
	// 深くネストされた子ノードに Pending タスクがある場合 true を返す
	tree := NewAttackDataTree("10.0.0.1", 2, 3)
	tree.AddPort(80, "http", "Apache")
	tree.AddEndpointWithStatus("10.0.0.1", 80, "", "/api", 301)   // redirect: EndpointEnum only
	tree.AddEndpointWithStatus("10.0.0.1", 80, "/api", "/api/v1", 200) // full recon

	// ポートレベル + 第1階層を Complete にする
	node := tree.Ports[0]
	node.SetAttackDataStatusForTest(TaskEndpointEnum, StatusComplete)
	node.SetAttackDataStatusForTest(TaskVhostDiscov, StatusComplete)
	apiChild := node.Children[0] // /api
	apiChild.SetAttackDataStatusForTest(TaskEndpointEnum, StatusComplete)

	// /api/v1 の param_fuzz は Pending のまま
	if !tree.PortHasPendingChildren(80) {
		t.Error("PortHasPendingChildren(80) = false, want true (deep nested pending task)")
	}
}

func TestPortHasPendingChildren_NonExistentPort(t *testing.T) {
	// 存在しないポートは false を返す
	tree := NewAttackDataTree("10.0.0.1", 2, 3)
	tree.AddPort(80, "http", "Apache")

	if tree.PortHasPendingChildren(443) {
		t.Error("PortHasPendingChildren(443) = true, want false (port does not exist)")
	}
}

// === FindPortNode tests ===

func TestFindPortNode_Found(t *testing.T) {
	tree := NewAttackDataTree("10.0.0.1", 2, 3)
	tree.AddPort(80, "http", "Apache")
	tree.AddPort(443, "https", "nginx")

	node := tree.FindPortNode(80)
	if node == nil {
		t.Fatal("FindPortNode(80) = nil, want non-nil")
	}
	if node.Port != 80 {
		t.Errorf("FindPortNode(80).Port = %d, want 80", node.Port)
	}
	if node.Service != "http" {
		t.Errorf("FindPortNode(80).Service = %q, want %q", node.Service, "http")
	}
}

func TestFindPortNode_NotFound(t *testing.T) {
	tree := NewAttackDataTree("10.0.0.1", 2, 3)
	tree.AddPort(80, "http", "Apache")

	node := tree.FindPortNode(8080)
	if node != nil {
		t.Errorf("FindPortNode(8080) = %v, want nil", node)
	}
}

// === Re-spawn limit tests ===

func TestAttackDataNode_SpawnCount_Increment(t *testing.T) {
	// StartPortRecon should increment SpawnCount each time it succeeds
	tree := NewAttackDataTree("10.0.0.1", 2, 3)
	tree.AddPort(80, "http", "Apache")
	node := tree.Ports[0]

	// First spawn
	ok := tree.StartPortRecon(node)
	if !ok {
		t.Fatal("StartPortRecon should succeed on first call")
	}
	if node.SpawnCount != 1 {
		t.Errorf("SpawnCount = %d after first StartPortRecon, want 1", node.SpawnCount)
	}

	// Complete the port so active goes down
	tree.CompleteAllPortTasks(80)

	// Re-add pending tasks to simulate new tasks discovered
	node.SetAttackDataStatusForTest(TaskEndpointEnum, StatusPending)

	// Second spawn
	ok = tree.StartPortRecon(node)
	if !ok {
		t.Fatal("StartPortRecon should succeed on second call")
	}
	if node.SpawnCount != 2 {
		t.Errorf("SpawnCount = %d after second StartPortRecon, want 2", node.SpawnCount)
	}
}

func TestAttackDataTree_SkipAllPendingChildren(t *testing.T) {
	tree := NewAttackDataTree("10.0.0.1", 2, 3)
	tree.AddPort(80, "http", "Apache")
	node := tree.Ports[0]

	// Add some endpoints with pending tasks
	tree.AddEndpoint("10.0.0.1", 80, "/", "/api")
	tree.AddEndpoint("10.0.0.1", 80, "/", "/admin")

	// Set some tasks to various statuses
	apiNode := node.Children[0]
	apiNode.SetAttackDataStatusForTest(TaskEndpointEnum, StatusComplete)
	apiNode.SetAttackDataStatusForTest(TaskParamFuzz, StatusPending)

	adminNode := node.Children[1]
	adminNode.SetAttackDataStatusForTest(TaskEndpointEnum, StatusPending)
	adminNode.SetAttackDataStatusForTest(TaskParamFuzz, StatusPending)

	// Port-level tasks: set endpoint_enum to Complete, vhost to Pending
	node.SetAttackDataStatusForTest(TaskEndpointEnum, StatusComplete)
	node.SetAttackDataStatusForTest(TaskVhostDiscov, StatusPending)

	// Skip all pending children
	tree.SkipAllPendingChildren(80)

	// Port-level pending tasks should be skipped
	if node.VhostDiscov != StatusSkipped {
		t.Errorf("port VhostDiscov = %d, want StatusSkipped(%d)", node.VhostDiscov, StatusSkipped)
	}
	// Port-level complete tasks should remain complete
	if node.EndpointEnum != StatusComplete {
		t.Errorf("port EndpointEnum = %d, want StatusComplete(%d)", node.EndpointEnum, StatusComplete)
	}

	// Child pending tasks should be skipped
	if apiNode.ParamFuzz != StatusSkipped {
		t.Errorf("api ParamFuzz = %d, want StatusSkipped(%d)", apiNode.ParamFuzz, StatusSkipped)
	}
	// Child complete tasks should remain complete
	if apiNode.EndpointEnum != StatusComplete {
		t.Errorf("api EndpointEnum = %d, want StatusComplete(%d)", apiNode.EndpointEnum, StatusComplete)
	}

	if adminNode.EndpointEnum != StatusSkipped {
		t.Errorf("admin EndpointEnum = %d, want StatusSkipped(%d)", adminNode.EndpointEnum, StatusSkipped)
	}
	if adminNode.ParamFuzz != StatusSkipped {
		t.Errorf("admin ParamFuzz = %d, want StatusSkipped(%d)", adminNode.ParamFuzz, StatusSkipped)
	}
}

func TestAttackDataTree_SkipAllPendingChildren_DeepNesting(t *testing.T) {
	tree := NewAttackDataTree("10.0.0.1", 2, 5)
	tree.AddPort(80, "http", "Apache")
	tree.AddEndpoint("10.0.0.1", 80, "/", "/api")
	tree.AddEndpoint("10.0.0.1", 80, "/api", "/api/v1")
	tree.AddEndpoint("10.0.0.1", 80, "/api/v1", "/api/v1/users")

	// All children should have pending tasks
	tree.SkipAllPendingChildren(80)

	// Walk and verify all pending became skipped
	var walk func(n *AttackDataNode)
	walk = func(n *AttackDataNode) {
		for _, st := range []AttackDataStatus{n.EndpointEnum, n.ParamFuzz, n.ValueFuzz, n.Profiling, n.VhostDiscov} {
			if st == StatusPending {
				t.Errorf("found StatusPending in node path=%s port=%d after SkipAllPendingChildren", n.Path, n.Port)
			}
		}
		for _, child := range n.Children {
			walk(child)
		}
	}
	node := tree.Ports[0]
	walk(node)
}

func TestStatusSkipped_Icon_And_Label(t *testing.T) {
	// statusIcon should return "[-]" for Skipped
	icon := statusIcon(StatusSkipped)
	if icon != "[-]" {
		t.Errorf("statusIcon(StatusSkipped) = %q, want %q", icon, "[-]")
	}

	// statusLabel should return "skipped"
	label := statusLabel(StatusSkipped)
	if label != "skipped" {
		t.Errorf("statusLabel(StatusSkipped) = %q, want %q", label, "skipped")
	}
}

func TestStatusSkipped_CountTasks(t *testing.T) {
	// Skipped tasks should count as total but not pending or complete
	tree := NewAttackDataTree("10.0.0.1", 2, 3)
	tree.AddPort(80, "http", "Apache")
	node := tree.Ports[0]

	node.SetAttackDataStatusForTest(TaskEndpointEnum, StatusSkipped)
	node.SetAttackDataStatusForTest(TaskVhostDiscov, StatusComplete)

	pending, complete, total := node.countTasks()
	if pending != 0 {
		t.Errorf("pending = %d, want 0", pending)
	}
	if complete != 1 {
		t.Errorf("complete = %d, want 1", complete)
	}
	if total != 2 {
		t.Errorf("total = %d, want 2 (skipped + complete)", total)
	}
}

func TestSpawnCount_JSON_RoundTrip(t *testing.T) {
	tree := NewAttackDataTree("10.0.0.1", 2, 3)
	tree.AddPort(80, "http", "Apache")
	node := tree.Ports[0]

	// Simulate 2 spawns
	tree.StartPortRecon(node)
	tree.CompleteAllPortTasks(80)
	node.SetAttackDataStatusForTest(TaskEndpointEnum, StatusPending)
	tree.StartPortRecon(node)
	tree.CompleteAllPortTasks(80)

	if node.SpawnCount != 2 {
		t.Fatalf("SpawnCount = %d before snapshot, want 2", node.SpawnCount)
	}

	// Snapshot → Restore → check SpawnCount preserved
	snap := tree.Snapshot()
	snapJSON, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	var restored AttackDataSnapshot
	if err := json.Unmarshal(snapJSON, &restored); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	tree2 := RestoreAttackDataTree(restored)
	if len(tree2.Ports) != 1 {
		t.Fatalf("restored ports = %d, want 1", len(tree2.Ports))
	}
	if tree2.Ports[0].SpawnCount != 2 {
		t.Errorf("restored SpawnCount = %d, want 2", tree2.Ports[0].SpawnCount)
	}
}

func TestStatusSkipped_NotCountedAsPending_InPortHasPendingChildren(t *testing.T) {
	tree := NewAttackDataTree("10.0.0.1", 2, 3)
	tree.AddPort(80, "http", "Apache")
	tree.AddEndpoint("10.0.0.1", 80, "/", "/api")

	// Set all children tasks to skipped
	tree.SkipAllPendingChildren(80)

	// PortHasPendingChildren should return false (skipped != pending)
	if tree.PortHasPendingChildren(80) {
		t.Error("PortHasPendingChildren should return false when all pending are skipped")
	}
}

func TestRollbackPortRecon(t *testing.T) {
	tree := NewAttackDataTree("10.0.0.1", 2, 0)
	tree.AddPort(80, "http", "Apache")
	port := tree.Ports[0]

	// StartPortRecon increments active and SpawnCount
	if !tree.StartPortRecon(port) {
		t.Fatal("StartPortRecon should succeed")
	}
	if tree.Active() != 1 {
		t.Fatalf("Active = %d, want 1", tree.Active())
	}
	if port.SpawnCount != 1 {
		t.Fatalf("SpawnCount = %d, want 1", port.SpawnCount)
	}

	// RollbackPortRecon reverses the effects
	tree.RollbackPortRecon(port)
	if tree.Active() != 0 {
		t.Errorf("Active = %d, want 0 after rollback", tree.Active())
	}
	if port.SpawnCount != 0 {
		t.Errorf("SpawnCount = %d, want 0 after rollback", port.SpawnCount)
	}

	// Tasks should be back to Pending
	for _, tt := range []ReconTaskType{TaskEndpointEnum, TaskVhostDiscov} {
		if port.getAttackDataStatus(tt) != StatusPending {
			t.Errorf("task %s should be Pending after rollback, got %d", tt, port.getAttackDataStatus(tt))
		}
	}
}

func TestRollbackPortRecon_ActiveFloor(t *testing.T) {
	// RollbackPortRecon should not decrement active below 0
	tree := NewAttackDataTree("10.0.0.1", 2, 0)
	tree.AddPort(80, "http", "Apache")
	port := tree.Ports[0]

	// Manually set active to 0 and call rollback — active should stay 0
	tree.RollbackPortRecon(port)
	if tree.Active() != 0 {
		t.Errorf("Active = %d, want 0 (should not go negative)", tree.Active())
	}
}

func TestRollbackPortRecon_OnlyInProgressReverted(t *testing.T) {
	// Only InProgress tasks should be reverted; Complete tasks should stay Complete
	tree := NewAttackDataTree("10.0.0.1", 2, 0)
	tree.AddPort(80, "http", "Apache")
	port := tree.Ports[0]

	// Start recon (marks Pending tasks as InProgress)
	tree.StartPortRecon(port)

	// Mark EndpointEnum as Complete (simulating partial completion)
	port.setAttackDataStatus(TaskEndpointEnum, StatusComplete)

	tree.RollbackPortRecon(port)

	// Complete task should stay Complete
	if port.getAttackDataStatus(TaskEndpointEnum) != StatusComplete {
		t.Errorf("EndpointEnum should remain Complete after rollback, got %d", port.getAttackDataStatus(TaskEndpointEnum))
	}

	// VhostDiscov was InProgress, should be back to Pending
	if port.getAttackDataStatus(TaskVhostDiscov) != StatusPending {
		t.Errorf("VhostDiscov should be Pending after rollback, got %d", port.getAttackDataStatus(TaskVhostDiscov))
	}
}
