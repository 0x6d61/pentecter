package agent_test

import (
	"testing"

	"github.com/0x6d61/pentecter/internal/agent"
)

func TestBuildTaskTree_GroupByPort(t *testing.T) {
	// 4つのサブタスクを作成
	task1 := agent.NewSubTask("task-1", agent.TaskKindRunner, "ssh scan")
	task1.Metadata = agent.TaskMetadata{Port: 22, Service: "ssh", Phase: "recon"}

	task2 := agent.NewSubTask("task-2", agent.TaskKindRunner, "http scan")
	task2.Metadata = agent.TaskMetadata{Port: 80, Service: "http", Phase: "recon"}

	task3 := agent.NewSubTask("task-3", agent.TaskKindSmart, "http enum")
	task3.Metadata = agent.TaskMetadata{Port: 80, Service: "http", Phase: "enum"}

	task4 := agent.NewSubTask("task-4", agent.TaskKindRunner, "general recon")
	// task4: port=0 (no port metadata)

	tasks := []*agent.SubTask{task1, task2, task3, task4}
	root := agent.BuildTaskTree("10.0.0.5", tasks)

	// ルートラベルの確認
	if root.Label != "10.0.0.5" {
		t.Errorf("root.Label: got %q, want %q", root.Label, "10.0.0.5")
	}

	// 3つの子ノード: "Port 22 (ssh)", "Port 80 (http)", "General"
	if len(root.Children) != 3 {
		t.Fatalf("root.Children: got %d, want 3", len(root.Children))
	}

	// ポート番号順にソートされるので Port 22 が最初
	if root.Children[0].Label != "Port 22 (ssh)" {
		t.Errorf("child[0].Label: got %q, want %q", root.Children[0].Label, "Port 22 (ssh)")
	}
	if len(root.Children[0].Tasks) != 1 {
		t.Errorf("Port 22 tasks: got %d, want 1", len(root.Children[0].Tasks))
	}

	if root.Children[1].Label != "Port 80 (http)" {
		t.Errorf("child[1].Label: got %q, want %q", root.Children[1].Label, "Port 80 (http)")
	}
	if len(root.Children[1].Tasks) != 2 {
		t.Errorf("Port 80 tasks: got %d, want 2", len(root.Children[1].Tasks))
	}

	if root.Children[2].Label != "General" {
		t.Errorf("child[2].Label: got %q, want %q", root.Children[2].Label, "General")
	}
	if len(root.Children[2].Tasks) != 1 {
		t.Errorf("General tasks: got %d, want 1", len(root.Children[2].Tasks))
	}
}

func TestBuildTaskTree_EmptyTasks(t *testing.T) {
	root := agent.BuildTaskTree("10.0.0.5", nil)

	if root.Label != "10.0.0.5" {
		t.Errorf("root.Label: got %q, want %q", root.Label, "10.0.0.5")
	}
	if len(root.Children) != 0 {
		t.Errorf("root.Children: got %d, want 0", len(root.Children))
	}
}

func TestBuildTaskTree_AllGeneral(t *testing.T) {
	task1 := agent.NewSubTask("task-1", agent.TaskKindRunner, "general scan 1")
	// port=0 (default)
	task2 := agent.NewSubTask("task-2", agent.TaskKindRunner, "general scan 2")
	// port=0 (default)

	tasks := []*agent.SubTask{task1, task2}
	root := agent.BuildTaskTree("10.0.0.5", tasks)

	if len(root.Children) != 1 {
		t.Fatalf("root.Children: got %d, want 1", len(root.Children))
	}
	if root.Children[0].Label != "General" {
		t.Errorf("child[0].Label: got %q, want %q", root.Children[0].Label, "General")
	}
	if len(root.Children[0].Tasks) != 2 {
		t.Errorf("General tasks: got %d, want 2", len(root.Children[0].Tasks))
	}
}
