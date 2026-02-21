package agent

import (
	"strings"
	"testing"
)

func TestNewReconTree(t *testing.T) {
	tree := NewReconTree("10.10.11.100", 0)
	if tree.Host != "10.10.11.100" {
		t.Errorf("Host = %q, want %q", tree.Host, "10.10.11.100")
	}
	// デフォルト MaxParallel = 2
	if tree.MaxParallel != 2 {
		t.Errorf("MaxParallel = %d, want 2", tree.MaxParallel)
	}

	tree2 := NewReconTree("10.10.11.100", 4)
	if tree2.MaxParallel != 4 {
		t.Errorf("MaxParallel = %d, want 4", tree2.MaxParallel)
	}
}

func TestAddPort_HTTP(t *testing.T) {
	tree := NewReconTree("10.10.11.100", 2)
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
	tree := NewReconTree("10.10.11.100", 2)
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
	tree := NewReconTree("10.10.11.100", 2)
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
	if child.Profiling != StatusPending {
		t.Errorf("Profiling = %d, want pending", child.Profiling)
	}
}

func TestAddEndpoint_Nested(t *testing.T) {
	tree := NewReconTree("10.10.11.100", 2)
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
	tree := NewReconTree("10.10.11.100", 2)
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
	tree := NewReconTree("10.10.11.100", 2)
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
	tree := NewReconTree("10.10.11.100", 2)
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
	tree := NewReconTree("10.10.11.100", 2)
	tree.AddPort(80, "http", "Apache")
	// HTTP ポート: EndpointEnum + VhostDiscov = 2 pending
	if got := tree.CountPending(); got != 2 {
		t.Errorf("CountPending = %d, want 2", got)
	}

	tree.AddEndpoint("10.10.11.100", 80, "/", "/api")
	// + EndpointEnum + ParamFuzz + Profiling = 5 pending
	if got := tree.CountPending(); got != 5 {
		t.Errorf("CountPending = %d, want 5", got)
	}

	tree.CompleteTask("10.10.11.100", 80, "/api", TaskEndpointEnum)
	if got := tree.CountPending(); got != 4 {
		t.Errorf("CountPending = %d, want 4", got)
	}
}

func TestCountTotal(t *testing.T) {
	tree := NewReconTree("10.10.11.100", 2)
	tree.AddPort(80, "http", "Apache")
	tree.AddPort(22, "ssh", "OpenSSH")
	tree.AddEndpoint("10.10.11.100", 80, "/", "/api")
	// HTTP ポート: 2 tasks + endpoint: 3 tasks = 5
	if got := tree.CountTotal(); got != 5 {
		t.Errorf("CountTotal = %d, want 5", got)
	}
}

func TestNextBatch_RespectsMaxParallel(t *testing.T) {
	tree := NewReconTree("10.10.11.100", 2)
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
	tree := NewReconTree("10.10.11.100", 10) // 高い max_parallel で全部返す
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
	tree := NewReconTree("10.10.11.100", 2)
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
	status := node.getReconStatus(task.Type)
	if status != StatusInProgress {
		t.Errorf("status = %d, want in_progress", status)
	}

	tree.FinishTask(task)
	if tree.active != 0 {
		t.Errorf("active = %d, want 0", tree.active)
	}
	status = node.getReconStatus(task.Type)
	if status != StatusComplete {
		t.Errorf("status = %d, want complete", status)
	}
}

func TestRenderTree(t *testing.T) {
	tree := NewReconTree("10.10.11.100", 2)
	tree.AddPort(22, "ssh", "OpenSSH 8.2")
	tree.AddPort(80, "http", "Apache 2.4.49")
	tree.AddEndpoint("10.10.11.100", 80, "/", "/api")
	tree.AddEndpoint("10.10.11.100", 80, "/", "/login")
	tree.CompleteTask("10.10.11.100", 80, "", TaskEndpointEnum)
	tree.CompleteTask("10.10.11.100", 80, "/login", TaskEndpointEnum)
	tree.CompleteTask("10.10.11.100", 80, "/login", TaskParamFuzz)
	tree.CompleteTask("10.10.11.100", 80, "/login", TaskProfiling)

	output := tree.RenderTree()

	// 基本的な内容が含まれるか確認
	checks := []string{
		"10.10.11.100",
		"22/ssh OpenSSH 8.2",
		"80/http Apache 2.4.49",
		"/api",
		"/login",
		"[x]",
		"[ ]",
		"Progress:",
	}
	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("RenderTree missing %q\noutput:\n%s", check, output)
		}
	}
}

func TestRenderQueue(t *testing.T) {
	tree := NewReconTree("10.10.11.100", 2)
	tree.AddPort(80, "http", "Apache")
	tree.AddEndpoint("10.10.11.100", 80, "/", "/api")

	output := tree.RenderQueue()

	checks := []string{
		"RECON QUEUE",
		"pending",
		"max_parallel=2",
	}
	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("RenderQueue missing %q\noutput:\n%s", check, output)
		}
	}
}

func TestRenderQueue_Empty(t *testing.T) {
	tree := NewReconTree("10.10.11.100", 2)
	output := tree.RenderQueue()
	if output != "" {
		t.Errorf("empty tree should return empty queue, got: %q", output)
	}
}

func TestReconTree_LockedByDefault(t *testing.T) {
	tree := NewReconTree("10.10.11.100", 2)
	if !tree.IsLocked() {
		t.Error("new ReconTree should be locked by default")
	}
}

func TestReconTree_UnlockManual(t *testing.T) {
	tree := NewReconTree("10.10.11.100", 2)
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

func TestReconTree_AutoUnlock_WhenNoPending(t *testing.T) {
	tree := NewReconTree("10.10.11.100", 2)
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

func TestReconTree_StaysLocked_WithPending(t *testing.T) {
	tree := NewReconTree("10.10.11.100", 2)
	tree.AddPort(80, "http", "Apache")
	tree.AddEndpoint("10.10.11.100", 80, "/", "/api")
	// まだ pending がある
	tree.CompleteTask("10.10.11.100", 80, "", TaskEndpointEnum)
	if !tree.IsLocked() {
		t.Error("should still be locked with remaining pending tasks")
	}
}

func TestRenderQueue_LockedMessage(t *testing.T) {
	tree := NewReconTree("10.10.11.100", 2)
	tree.AddPort(80, "http", "Apache")

	output := tree.RenderQueue()
	// locked 状態では強制文言が含まれる
	if !strings.Contains(output, "MANDATORY") {
		t.Errorf("locked RenderQueue should contain MANDATORY, got:\n%s", output)
	}
}

func TestRenderQueue_UnlockedNoForceMessage(t *testing.T) {
	tree := NewReconTree("10.10.11.100", 2)
	tree.AddPort(80, "http", "Apache")
	tree.Unlock()

	output := tree.RenderQueue()
	// unlocked 状態では強制文言が含まれない
	if strings.Contains(output, "MANDATORY") {
		t.Errorf("unlocked RenderQueue should NOT contain MANDATORY, got:\n%s", output)
	}
}

func TestAddFinding(t *testing.T) {
	tree := NewReconTree("10.10.11.100", 2)
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
	tree := NewReconTree("10.10.11.100", 2)
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
	tree := NewReconTree("10.10.11.100", 2)
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
	tree := NewReconTree("10.10.11.100", 2)
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
	tree := NewReconTree("10.10.11.100", 2)
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

// --- renderActiveTasks カバレッジ ---

func TestRenderTree_WithActiveTasks(t *testing.T) {
	// StartTask で in_progress にした後、RenderTree に "[>]" と "[active]" が含まれること
	tree := NewReconTree("10.10.11.100", 2)
	tree.AddPort(80, "http", "Apache")

	batch := tree.NextBatch()
	if len(batch) == 0 {
		t.Fatal("NextBatch returned empty")
	}
	// タスクを開始 → in_progress
	tree.StartTask(batch[0])

	output := tree.RenderTree()

	// "[>]" は StatusInProgress の表示
	if !strings.Contains(output, "[>]") {
		t.Errorf("RenderTree should contain '[>]' for active task\noutput:\n%s", output)
	}

	// RenderQueue で "[active]" が含まれること
	queue := tree.RenderQueue()
	if !strings.Contains(queue, "[active]") {
		t.Errorf("RenderQueue should contain '[active]' for in-progress task\noutput:\n%s", queue)
	}
}

// --- renderEndpointNode with findings AND children ---

func TestRenderTree_FindingsAndChildren(t *testing.T) {
	// エンドポイントに finding と子エンドポイントの両方がある場合、
	// ツリーレンダリングで両方が正しく表示されること
	tree := NewReconTree("10.10.11.100", 2)
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
	tree := NewReconTree("10.10.11.100", 2)
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
	tree := NewReconTree("10.10.11.100", 2)
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
	tree := NewReconTree("10.10.11.100", 2)
	tree.AddPort(80, "http", "Apache")

	// StartTask で全タスクを InProgress にする
	node := tree.Ports[0]
	for _, tt := range []ReconTaskType{TaskEndpointEnum, TaskParamFuzz, TaskProfiling, TaskVhostDiscov} {
		task := &ReconTask{Type: tt, Node: node, Host: node.Host, Port: node.Port}
		tree.StartTask(task)
	}

	if tree.active != 4 {
		t.Fatalf("active = %d, want 4", tree.active)
	}

	// CompleteAllPortTasks で全タスクを Complete にする
	tree.CompleteAllPortTasks(80)

	// active が 0 になること
	if tree.active != 0 {
		t.Errorf("active = %d, want 0 after CompleteAllPortTasks", tree.active)
	}

	// 全タスクが Complete であること
	for _, tt := range []ReconTaskType{TaskEndpointEnum, TaskParamFuzz, TaskProfiling, TaskVhostDiscov} {
		if node.getReconStatus(tt) != StatusComplete {
			t.Errorf("task %v status = %d, want complete", tt, node.getReconStatus(tt))
		}
	}
}

func TestCompleteAllPortTasks_OnlyInProgress(t *testing.T) {
	// InProgress のタスクのみ Complete にし、Pending はスキップすること
	tree := NewReconTree("10.10.11.100", 2)
	tree.AddPort(80, "http", "Apache")

	node := tree.Ports[0]
	// EndpointEnum だけ InProgress にする
	task := &ReconTask{Type: TaskEndpointEnum, Node: node, Host: node.Host, Port: node.Port}
	tree.StartTask(task)

	if tree.active != 1 {
		t.Fatalf("active = %d, want 1", tree.active)
	}

	tree.CompleteAllPortTasks(80)

	// active が 0 になること
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
	tree := NewReconTree("10.10.11.100", 2)
	tree.AddPort(80, "http", "Apache")

	node := tree.Ports[0]
	task := &ReconTask{Type: TaskEndpointEnum, Node: node, Host: node.Host, Port: node.Port}
	tree.StartTask(task)

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
	tree := NewReconTree("10.10.11.100", 4)
	tree.AddPort(80, "http", "Apache")
	tree.AddPort(443, "https", "nginx")

	// 両方の EndpointEnum を InProgress にする
	for _, node := range tree.Ports {
		task := &ReconTask{Type: TaskEndpointEnum, Node: node, Host: node.Host, Port: node.Port}
		tree.StartTask(task)
	}

	if tree.active != 2 {
		t.Fatalf("active = %d, want 2", tree.active)
	}

	// port 80 だけ Complete にする
	tree.CompleteAllPortTasks(80)

	// active は 1（port 443 の分だけ残る）
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
