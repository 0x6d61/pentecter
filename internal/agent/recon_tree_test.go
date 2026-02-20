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
