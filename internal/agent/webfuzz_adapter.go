package agent

import "github.com/0x6d61/pentecter/internal/tools/webfuzz"

// webfuzzTreeAdapter は AttackDataTree を webfuzz.TreeUpdater インターフェースに適合させるアダプター。
// ReconTaskType（int ベース型）→ int の型変換を行う。
type webfuzzTreeAdapter struct {
	tree *AttackDataTree
}

var _ webfuzz.TreeUpdater = (*webfuzzTreeAdapter)(nil)

func (a *webfuzzTreeAdapter) AddEndpointWithStatus(host string, port int, parentPath, newPath string, httpStatus int) {
	if a.tree == nil {
		return
	}
	a.tree.AddEndpointWithStatus(host, port, parentPath, newPath, httpStatus)
}

func (a *webfuzzTreeAdapter) AddVhost(parentHost string, port int, vhostName string) {
	if a.tree == nil {
		return
	}
	a.tree.AddVhost(parentHost, port, vhostName)
}

func (a *webfuzzTreeAdapter) CompleteTask(host string, port int, path string, taskType int) {
	if a.tree == nil {
		return
	}
	rt := ReconTaskType(taskType)
	// 有効範囲外の taskType は無視（バグの静かな進行を防ぐ）
	if rt < TaskEndpointEnum || rt > TaskVhostDiscov {
		return
	}
	a.tree.CompleteTask(host, port, path, rt)
}

func (a *webfuzzTreeAdapter) AddParameter(host string, port int, path string, name string, paramType string) {
	if a.tree == nil {
		return
	}
	a.tree.AddParameter(host, port, path, name, paramType)
}

func (a *webfuzzTreeAdapter) AddFinding(host string, port int, path string, param, category, evidence, severity string) {
	if a.tree == nil {
		return
	}
	a.tree.AddFinding(host, port, path, Finding{
		Param:    param,
		Category: category,
		Evidence: evidence,
		Severity: severity,
	})
}
