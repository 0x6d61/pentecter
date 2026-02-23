package agent

import (
	"testing"
)

func TestWebfuzzTreeAdapter_NilTree(t *testing.T) {
	// tree が nil でも panic しないこと
	adapter := &webfuzzTreeAdapter{tree: nil}

	// 各メソッドが panic せず正常に返ること
	adapter.AddEndpointWithStatus("10.0.0.1", 80, "/", "/admin", 200)
	adapter.AddVhost("10.0.0.1", 80, "dev.example.com")
	adapter.CompleteTask("10.0.0.1", 80, "/", 0)
	adapter.AddParameter("10.0.0.1", 80, "/", "id", "query")
	adapter.AddFinding("10.0.0.1", 80, "/", "id", "sqli", "error", "high")
}

func TestWebfuzzTreeAdapter_InvalidTaskType(t *testing.T) {
	tree := NewAttackDataTree("10.0.0.1", 2, 3)
	tree.AddPort(80, "http", "Apache")
	adapter := &webfuzzTreeAdapter{tree: tree}

	// 有効範囲外の taskType は無視されること（panic しない）
	adapter.CompleteTask("10.0.0.1", 80, "/", -1)
	adapter.CompleteTask("10.0.0.1", 80, "/", 99)

	// 有効な taskType は正常に処理されること
	adapter.CompleteTask("10.0.0.1", 80, "/", int(TaskEndpointEnum))

	// ステータスが Complete になっていること
	tree.mu.RLock()
	defer tree.mu.RUnlock()
	if len(tree.Ports) == 0 {
		t.Fatal("expected port node")
	}
	node := tree.Ports[0]
	if node.EndpointEnum != StatusComplete {
		t.Errorf("EndpointEnum = %d, want StatusComplete(%d)", node.EndpointEnum, StatusComplete)
	}
}

func TestWebfuzzTreeAdapter_DelegatesCorrectly(t *testing.T) {
	tree := NewAttackDataTree("10.0.0.1", 2, 3)
	tree.AddPort(80, "http", "Apache")
	adapter := &webfuzzTreeAdapter{tree: tree}

	// AddEndpointWithStatus のデリゲーション
	adapter.AddEndpointWithStatus("10.0.0.1", 80, "/", "/login", 200)
	tree.mu.RLock()
	found := false
	for _, child := range tree.Ports[0].Children {
		if child.Path == "/login" {
			found = true
		}
	}
	tree.mu.RUnlock()
	if !found {
		t.Error("expected /login endpoint to be added via adapter")
	}

	// AddVhost のデリゲーション
	adapter.AddVhost("10.0.0.1", 80, "dev.example.com")
	tree.mu.RLock()
	if len(tree.Vhosts) == 0 {
		t.Error("expected vhost to be added via adapter")
	}
	tree.mu.RUnlock()
}

// --- 統合テスト: webfuzz adapter → AttackDataTree パイプライン ---

func TestWebfuzzTreeAdapter_EndpointPipeline(t *testing.T) {
	// webfuzz dir モードのフルパイプライン:
	// WebfuzzTool.hitFn → webfuzzTreeAdapter.AddEndpointWithStatus → AttackDataTree.AddEndpointWithStatus
	tree := NewAttackDataTree("172.30.0.30", 2, 3)
	tree.AddPort(80, "http", "Apache")
	adapter := &webfuzzTreeAdapter{tree: tree}

	// webfuzz の hitFn が呼ぶのと同じ引数パターンをシミュレート
	// webfuzz dir -u http://172.30.0.30/FUZZ → parentPath="/", newPath="/admin", httpStatus=200
	adapter.AddEndpointWithStatus("172.30.0.30", 80, "/", "/admin", 200)
	adapter.AddEndpointWithStatus("172.30.0.30", 80, "/", "/login", 200)
	adapter.AddEndpointWithStatus("172.30.0.30", 80, "/", "/api", 301)

	// ツリーに子ノードが追加されたか確認
	tree.mu.RLock()
	defer tree.mu.RUnlock()

	if len(tree.Ports) == 0 {
		t.Fatal("expected port node")
	}
	node := tree.Ports[0]
	if len(node.Children) != 3 {
		t.Fatalf("expected 3 children, got %d", len(node.Children))
	}

	// 各子ノードのパスとステータスを確認
	paths := map[string]bool{}
	for _, child := range node.Children {
		paths[child.Path] = true
		// ホスト名が正しく設定されているか
		if child.Host != "172.30.0.30" {
			t.Errorf("child %s: Host = %q, want %q", child.Path, child.Host, "172.30.0.30")
		}
		// ポートが正しく設定されているか
		if child.Port != 80 {
			t.Errorf("child %s: Port = %d, want 80", child.Path, child.Port)
		}
	}

	for _, path := range []string{"/admin", "/login", "/api"} {
		if !paths[path] {
			t.Errorf("expected child path %s", path)
		}
	}

	// /attackdata コマンドで表示される RenderTree に反映されているか
	rendered := tree.RenderTree()
	for _, path := range []string{"/admin", "/login", "/api"} {
		if !contains(rendered, path) {
			t.Errorf("RenderTree should contain %s, got:\n%s", path, rendered)
		}
	}
}

func TestWebfuzzTreeAdapter_AddParameter(t *testing.T) {
	// Bug 3: param モードで発見したパラメーター名がツリーに記録されること
	tree := NewAttackDataTree("10.0.0.1", 2, 3)
	tree.AddPort(80, "http", "Apache")
	// エンドポイントを追加
	tree.AddEndpointWithStatus("10.0.0.1", 80, "/", "/login", 200)

	adapter := &webfuzzTreeAdapter{tree: tree}

	// AddParameter を呼ぶ（TreeUpdater インターフェースに追加予定）
	adapter.AddParameter("10.0.0.1", 80, "/login", "username", "query")
	adapter.AddParameter("10.0.0.1", 80, "/login", "password", "query")

	// パラメーターが記録されたか確認
	tree.mu.RLock()
	defer tree.mu.RUnlock()

	portNode := tree.Ports[0]
	if len(portNode.Children) == 0 {
		t.Fatal("expected /login endpoint")
	}
	loginNode := portNode.Children[0]
	if len(loginNode.Parameters) != 2 {
		t.Fatalf("expected 2 parameters, got %d", len(loginNode.Parameters))
	}
	if loginNode.Parameters[0].Name != "username" {
		t.Errorf("expected first param name 'username', got %q", loginNode.Parameters[0].Name)
	}
	if loginNode.Parameters[1].Name != "password" {
		t.Errorf("expected second param name 'password', got %q", loginNode.Parameters[1].Name)
	}
}

func TestWebfuzzTreeAdapter_AddFinding(t *testing.T) {
	// Bug 4: TreeUpdater 経由で finding を追加できること
	tree := NewAttackDataTree("10.0.0.1", 2, 3)
	tree.AddPort(80, "http", "Apache")
	tree.AddEndpointWithStatus("10.0.0.1", 80, "/", "/login", 200)

	adapter := &webfuzzTreeAdapter{tree: tree}

	// AddFinding を呼ぶ（フラットパラメータ → adapter 内で Finding 構造体に変換）
	adapter.AddFinding("10.0.0.1", 80, "/login", "username", "sqli", "500 + MySQL syntax error on single quote", "high")

	// finding が記録されたか確認
	tree.mu.RLock()
	defer tree.mu.RUnlock()

	portNode := tree.Ports[0]
	loginNode := portNode.Children[0]
	if len(loginNode.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(loginNode.Findings))
	}
	if loginNode.Findings[0].Category != "sqli" {
		t.Errorf("expected finding category 'sqli', got %q", loginNode.Findings[0].Category)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
