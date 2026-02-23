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
