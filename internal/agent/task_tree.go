package agent

import (
	"fmt"
	"sort"
)

// TaskTreeNode はタスクツリーの1ノード。
type TaskTreeNode struct {
	Label    string          // 表示ラベル
	Tasks    []*SubTask      // このノードに属するタスク
	Children []*TaskTreeNode // 子ノード
}

// BuildTaskTree はターゲットの全 SubTask からツリー構造を自動生成する。
// ポート番号ごとにグループ化し、ポート未指定（0）のタスクは "General" にまとめる。
func BuildTaskTree(targetHost string, tasks []*SubTask) *TaskTreeNode {
	root := &TaskTreeNode{Label: targetHost}

	type portKey struct {
		Port    int
		Service string
	}
	portGroups := map[portKey]*TaskTreeNode{}
	var general []*SubTask
	var portKeys []portKey // 順序保持用

	for _, task := range tasks {
		meta := task.GetMetadata()

		if meta.Port > 0 {
			key := portKey{Port: meta.Port, Service: meta.Service}
			node, ok := portGroups[key]
			if !ok {
				label := fmt.Sprintf("Port %d", meta.Port)
				if meta.Service != "" {
					label += fmt.Sprintf(" (%s)", meta.Service)
				}
				node = &TaskTreeNode{Label: label}
				portGroups[key] = node
				portKeys = append(portKeys, key)
			}
			node.Tasks = append(node.Tasks, task)
		} else {
			general = append(general, task)
		}
	}

	// ポート番号順にソート
	sort.Slice(portKeys, func(i, j int) bool {
		return portKeys[i].Port < portKeys[j].Port
	})

	for _, key := range portKeys {
		root.Children = append(root.Children, portGroups[key])
	}

	if len(general) > 0 {
		root.Children = append(root.Children, &TaskTreeNode{Label: "General", Tasks: general})
	}

	return root
}
