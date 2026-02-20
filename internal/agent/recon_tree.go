package agent

import (
	"fmt"
	"strings"
)

// ReconStatus は偵察タスクの状態
type ReconStatus int

const (
	// StatusNone はタスクが存在しない（非 HTTP ポート等）
	StatusNone ReconStatus = iota
	// StatusPending は未実行
	StatusPending
	// StatusInProgress は実行中
	StatusInProgress
	// StatusComplete は完了
	StatusComplete
)

// ReconTaskType は偵察タスクの種類
type ReconTaskType int

const (
	TaskEndpointEnum ReconTaskType = iota
	TaskParamFuzz
	TaskProfiling
	TaskVhostDiscov
)

func (t ReconTaskType) String() string {
	switch t {
	case TaskEndpointEnum:
		return "endpoint_enum"
	case TaskParamFuzz:
		return "param_fuzz"
	case TaskProfiling:
		return "profiling"
	case TaskVhostDiscov:
		return "vhost_discovery"
	default:
		return "unknown"
	}
}

// ReconNode はツリーの各ノード
type ReconNode struct {
	Host    string // "10.10.11.100" or "dev.example.com" (vhost)
	Port    int    // 80, 443, 22... (0 = endpoint node)
	Service string // "http", "ssh", "smb"
	Banner  string // "Apache 2.4.49", "OpenSSH 8.2"
	Path    string // "/", "/api", "/api/v1" (endpoint nodes only)

	// タスクステータス（ノードタイプによって使うフィールドが異なる）
	EndpointEnum ReconStatus
	ParamFuzz    ReconStatus
	Profiling    ReconStatus
	VhostDiscov  ReconStatus

	Children []*ReconNode
}

// isHTTP は HTTP/HTTPS サービスかどうか
func (n *ReconNode) isHTTP() bool {
	return n.Service == "http" || n.Service == "https" ||
		n.Service == "http-proxy" || n.Service == "https-alt"
}

// getReconStatus は指定タスクタイプのステータスを返す
func (n *ReconNode) getReconStatus(taskType ReconTaskType) ReconStatus {
	switch taskType {
	case TaskEndpointEnum:
		return n.EndpointEnum
	case TaskParamFuzz:
		return n.ParamFuzz
	case TaskProfiling:
		return n.Profiling
	case TaskVhostDiscov:
		return n.VhostDiscov
	default:
		return StatusNone
	}
}

// setReconStatus は指定タスクタイプのステータスを設定する
func (n *ReconNode) setReconStatus(taskType ReconTaskType, status ReconStatus) {
	switch taskType {
	case TaskEndpointEnum:
		n.EndpointEnum = status
	case TaskParamFuzz:
		n.ParamFuzz = status
	case TaskProfiling:
		n.Profiling = status
	case TaskVhostDiscov:
		n.VhostDiscov = status
	}
}

// countTasks はノードとその子孫の pending/complete/total を再帰的に数える
func (n *ReconNode) countTasks() (pending, complete, total int) {
	for _, st := range []ReconStatus{n.EndpointEnum, n.ParamFuzz, n.Profiling, n.VhostDiscov} {
		switch st {
		case StatusPending:
			pending++
			total++
		case StatusInProgress:
			total++
		case StatusComplete:
			complete++
			total++
		}
	}
	for _, child := range n.Children {
		p, c, t := child.countTasks()
		pending += p
		complete += c
		total += t
	}
	return
}

// ReconTask は pending キューの1エントリ
type ReconTask struct {
	Type ReconTaskType
	Node *ReconNode
	Host string
	Port int
	Path string
}

// ReconTree はターゲットの偵察状態を管理するツリー
type ReconTree struct {
	Host        string
	MaxParallel int
	active      int
	locked      bool         // RECON フェーズがロック中か（true = pending タスク完了まで遷移不可）
	Ports       []*ReconNode // ポートレベルノード
	Vhosts      []*ReconNode // vhost ルートノード
}

// NewReconTree は新しい ReconTree を作成する。maxParallel が 0 ならデフォルト 2。
func NewReconTree(host string, maxParallel int) *ReconTree {
	if maxParallel <= 0 {
		maxParallel = 2
	}
	return &ReconTree{
		Host:        host,
		MaxParallel: maxParallel,
		locked:      true,
	}
}

// AddPort は nmap で発見したポートをツリーに追加する。
// HTTP 系なら EndpointEnum + VhostDiscov を pending にする。
func (t *ReconTree) AddPort(port int, service, banner string) {
	node := &ReconNode{
		Host:    t.Host,
		Port:    port,
		Service: service,
		Banner:  banner,
	}
	if node.isHTTP() {
		node.EndpointEnum = StatusPending
		node.VhostDiscov = StatusPending
	}
	t.Ports = append(t.Ports, node)
}

// AddEndpoint は ffuf で発見した endpoint を親ノードの子として追加する。
// EndpointEnum + ParamFuzz + Profiling を pending にする。
func (t *ReconTree) AddEndpoint(host string, port int, parentPath, newPath string) {
	parent := t.findNode(host, port, parentPath)
	if parent == nil {
		return
	}
	child := &ReconNode{
		Host:         host,
		Port:         port,
		Path:         newPath,
		EndpointEnum: StatusPending,
		ParamFuzz:    StatusPending,
		Profiling:    StatusPending,
	}
	parent.Children = append(parent.Children, child)
}

// AddVhost は ffuf で発見した仮想ホストをツリーに追加する。
// VhostDiscov + EndpointEnum を pending にする。
func (t *ReconTree) AddVhost(parentHost string, port int, vhostName string) {
	node := &ReconNode{
		Host:         vhostName,
		Port:         port,
		Service:      "http", // vhost は HTTP 前提
		EndpointEnum: StatusPending,
		VhostDiscov:  StatusPending,
	}
	t.Vhosts = append(t.Vhosts, node)
}

// CompleteTask は指定タスクを完了にする。
// path が空文字列の場合はポートレベルノードを対象とする。
func (t *ReconTree) CompleteTask(host string, port int, path string, taskType ReconTaskType) {
	node := t.findNode(host, port, path)
	if node == nil {
		return
	}
	node.setReconStatus(taskType, StatusComplete)
}

// HasPending はツリーに pending タスクがあるか
func (t *ReconTree) HasPending() bool {
	return t.CountPending() > 0
}

// CountPending は pending タスクの総数
func (t *ReconTree) CountPending() int {
	pending := 0
	for _, node := range t.Ports {
		p, _, _ := node.countTasks()
		pending += p
	}
	for _, node := range t.Vhosts {
		p, _, _ := node.countTasks()
		pending += p
	}
	return pending
}

// CountComplete は完了タスクの総数
func (t *ReconTree) CountComplete() int {
	complete := 0
	for _, node := range t.Ports {
		_, c, _ := node.countTasks()
		complete += c
	}
	for _, node := range t.Vhosts {
		_, c, _ := node.countTasks()
		complete += c
	}
	return complete
}

// CountTotal は全タスクの総数
func (t *ReconTree) CountTotal() int {
	total := 0
	for _, node := range t.Ports {
		_, _, tt := node.countTasks()
		total += tt
	}
	for _, node := range t.Vhosts {
		_, _, tt := node.countTasks()
		total += tt
	}
	return total
}

// IsLocked は RECON フェーズがロックされているか返す。
// タスクが存在し、かつ pending がなければ自動解除する。
func (t *ReconTree) IsLocked() bool {
	if t.locked && t.CountTotal() > 0 && !t.HasPending() {
		t.locked = false
	}
	return t.locked
}

// Unlock は RECON フェーズロックを手動解除する。
func (t *ReconTree) Unlock() {
	t.locked = false
}

// NextBatch は MaxParallel - active 個の pending タスクを優先順で返す。
// 優先順: endpoint_enum > param_fuzz > profiling > vhost_discovery
func (t *ReconTree) NextBatch() []*ReconTask {
	available := t.MaxParallel - t.active
	if available <= 0 {
		return nil
	}

	var tasks []*ReconTask
	// 優先順にタスクを収集
	for _, taskType := range []ReconTaskType{TaskEndpointEnum, TaskParamFuzz, TaskProfiling, TaskVhostDiscov} {
		t.collectPending(&tasks, taskType, available)
		if len(tasks) >= available {
			break
		}
	}

	if len(tasks) > available {
		tasks = tasks[:available]
	}
	return tasks
}

// collectPending は指定タイプの pending タスクを DFS で収集する
func (t *ReconTree) collectPending(tasks *[]*ReconTask, taskType ReconTaskType, limit int) {
	for _, node := range t.Ports {
		if len(*tasks) >= limit {
			return
		}
		t.collectPendingFromNode(tasks, node, taskType, limit)
	}
	for _, node := range t.Vhosts {
		if len(*tasks) >= limit {
			return
		}
		t.collectPendingFromNode(tasks, node, taskType, limit)
	}
}

func (t *ReconTree) collectPendingFromNode(tasks *[]*ReconTask, node *ReconNode, taskType ReconTaskType, limit int) {
	if len(*tasks) >= limit {
		return
	}
	if node.getReconStatus(taskType) == StatusPending {
		*tasks = append(*tasks, &ReconTask{
			Type: taskType,
			Node: node,
			Host: node.Host,
			Port: node.Port,
			Path: node.Path,
		})
	}
	for _, child := range node.Children {
		if len(*tasks) >= limit {
			return
		}
		t.collectPendingFromNode(tasks, child, taskType, limit)
	}
}

// StartTask はタスクを実行中にし、active カウントを増やす
func (t *ReconTree) StartTask(task *ReconTask) {
	task.Node.setReconStatus(task.Type, StatusInProgress)
	t.active++
}

// FinishTask はタスクを完了にし、active カウントを減らす
func (t *ReconTree) FinishTask(task *ReconTask) {
	task.Node.setReconStatus(task.Type, StatusComplete)
	if t.active > 0 {
		t.active--
	}
}

// findNode はホスト/ポート/パスでノードを検索する。
// path が "/" かつポートノードの Path が "" の場合はポートノード自身を返す（ルート扱い）。
func (t *ReconTree) findNode(host string, port int, path string) *ReconNode {
	// ポートノードを探索
	for _, node := range t.Ports {
		if node.Host == host && node.Port == port && matchPath(node.Path, path) {
			return node
		}
		if found := findNodeRecursive(node, host, port, path); found != nil {
			return found
		}
	}
	// vhost ノードを探索
	for _, node := range t.Vhosts {
		if node.Host == host && node.Port == port && matchPath(node.Path, path) {
			return node
		}
		if found := findNodeRecursive(node, host, port, path); found != nil {
			return found
		}
	}
	return nil
}

// matchPath はパスの一致判定。"" と "/" は同一視する。
func matchPath(nodePath, searchPath string) bool {
	if nodePath == searchPath {
		return true
	}
	// ポートノード（Path=""）は "/" でも一致
	if (nodePath == "" && searchPath == "/") || (nodePath == "/" && searchPath == "") {
		return true
	}
	return false
}

func findNodeRecursive(node *ReconNode, host string, port int, path string) *ReconNode {
	for _, child := range node.Children {
		if child.Host == host && child.Port == port && child.Path == path {
			return child
		}
		if found := findNodeRecursive(child, host, port, path); found != nil {
			return found
		}
	}
	return nil
}

// statusIcon はステータスの ASCII 表現
func statusIcon(s ReconStatus) string {
	switch s {
	case StatusComplete:
		return "[x]"
	case StatusInProgress:
		return "[>]"
	case StatusPending:
		return "[ ]"
	default:
		return ""
	}
}

// RenderTree は ASCII ツリーを返す（/recontree 用）
func (t *ReconTree) RenderTree() string {
	var sb strings.Builder
	sb.WriteString(t.Host)
	sb.WriteString("\n")

	allNodes := make([]*ReconNode, 0, len(t.Ports)+len(t.Vhosts))
	allNodes = append(allNodes, t.Ports...)
	// vhost はラベル付きで追加
	allNodes = append(allNodes, t.Vhosts...)

	for i, node := range allNodes {
		isLast := i == len(allNodes)-1
		prefix := "|-- "
		if isLast {
			prefix = "+-- "
		}
		childPrefix := "|   "
		if isLast {
			childPrefix = "    "
		}

		isVhost := i >= len(t.Ports)
		renderNode(&sb, node, prefix, childPrefix, isVhost)
	}

	// Progress 行
	complete := t.CountComplete()
	total := t.CountTotal()
	if total > 0 {
		pct := complete * 100 / total
		fmt.Fprintf(&sb, "\nProgress: %d/%d tasks complete (%d%%)\n", complete, total, pct)
	}
	if t.active > 0 || t.MaxParallel > 0 {
		fmt.Fprintf(&sb, "Active: %d/%d\n", t.active, t.MaxParallel)
	}

	return sb.String()
}

func renderNode(sb *strings.Builder, node *ReconNode, prefix, childPrefix string, isVhost bool) {
	if node.Port > 0 && node.Path == "" {
		// ポートレベルノード
		if isVhost {
			fmt.Fprintf(sb, "%s[vhost] %s (%d/%s)", prefix, node.Host, node.Port, node.Service)
		} else {
			fmt.Fprintf(sb, "%s%d/%s %s", prefix, node.Port, node.Service, node.Banner)
		}

		if node.isHTTP() {
			// vhost + endpoint ステータス表示
			sb.WriteString("\n")
			hasChildren := len(node.Children) > 0
			vhostPrefix := childPrefix + "|-- "
			if !hasChildren {
				vhostPrefix = childPrefix + "+-- "
			}
			fmt.Fprintf(sb, "%svhost %s\n", vhostPrefix, statusIcon(node.VhostDiscov))

			// endpoint ノードのステータス（ルートレベル）
			rootStatus := ""
			if node.EndpointEnum != StatusNone {
				rootStatus = fmt.Sprintf("%s%s%s",
					statusIcon(node.EndpointEnum),
					statusIcon(node.ParamFuzz),
					statusIcon(node.Profiling))
			}
			if rootStatus != "" && !hasChildren {
				fmt.Fprintf(sb, "%s/ %s\n", childPrefix+"+-- ", rootStatus)
			} else if rootStatus != "" {
				fmt.Fprintf(sb, "%s/ %s\n", childPrefix+"|-- ", rootStatus)
			}

			// 子ノード
			for j, child := range node.Children {
				isLastChild := j == len(node.Children)-1
				cp := childPrefix + "|-- "
				ccp := childPrefix + "|   "
				if isLastChild {
					cp = childPrefix + "+-- "
					ccp = childPrefix + "    "
				}
				renderEndpointNode(sb, child, cp, ccp)
			}
		} else {
			sb.WriteString("\n")
		}
	} else {
		// endpoint ノード
		renderEndpointNode(sb, node, prefix, childPrefix)
	}
}

func renderEndpointNode(sb *strings.Builder, node *ReconNode, prefix, childPrefix string) {
	status := fmt.Sprintf("%s%s%s",
		statusIcon(node.EndpointEnum),
		statusIcon(node.ParamFuzz),
		statusIcon(node.Profiling))
	fmt.Fprintf(sb, "%s%s %s\n", prefix, node.Path, status)

	for j, child := range node.Children {
		isLast := j == len(node.Children)-1
		cp := childPrefix + "|-- "
		ccp := childPrefix + "|   "
		if isLast {
			cp = childPrefix + "+-- "
			ccp = childPrefix + "    "
		}
		renderEndpointNode(sb, child, cp, ccp)
	}
}

// RenderQueue は RECON QUEUE をプロンプト注入用に返す。
// pending がない場合は空文字列を返す。
func (t *ReconTree) RenderQueue() string {
	if !t.HasPending() {
		return ""
	}

	pending := t.CountPending()
	var sb strings.Builder
	fmt.Fprintf(&sb, "RECON QUEUE (%d pending, %d active, max_parallel=%d):\n",
		pending, t.active, t.MaxParallel)

	if t.locked {
		sb.WriteString("MANDATORY: You MUST complete ALL pending recon tasks before proceeding to RECORD/ANALYZE.\n")
		sb.WriteString("Execute the [next] task below. Do NOT skip to other workflow phases.\n\n")
	}

	// active タスクを表示
	t.renderActiveTasks(&sb)

	// pending タスクを優先順で表示（最大10個）
	shown := 0
	first := true
	for _, taskType := range []ReconTaskType{TaskEndpointEnum, TaskParamFuzz, TaskProfiling, TaskVhostDiscov} {
		for _, node := range t.allNodes() {
			if shown >= 10 {
				break
			}
			if node.getReconStatus(taskType) == StatusPending {
				label := "queued"
				if first {
					label = "next"
					first = false
				}
				host := node.Host
				if host == "" {
					host = t.Host
				}
				path := node.Path
				if path == "" {
					path = "/"
				}
				fmt.Fprintf(&sb, "  [%s]  %s: %s on %s:%d\n",
					label, taskType, path, host, node.Port)
				shown++
			}
		}
	}

	return sb.String()
}

// renderActiveTasks は実行中のタスクを表示する
func (t *ReconTree) renderActiveTasks(sb *strings.Builder) {
	for _, taskType := range []ReconTaskType{TaskEndpointEnum, TaskParamFuzz, TaskProfiling, TaskVhostDiscov} {
		for _, node := range t.allNodes() {
			if node.getReconStatus(taskType) == StatusInProgress {
				host := node.Host
				if host == "" {
					host = t.Host
				}
				path := node.Path
				if path == "" {
					path = "/"
				}
				fmt.Fprintf(sb, "  [active] %s: %s on %s:%d\n",
					taskType, path, host, node.Port)
			}
		}
	}
}

// allNodes はポート + vhost + 全子ノードをフラットに返す
func (t *ReconTree) allNodes() []*ReconNode {
	var nodes []*ReconNode
	for _, node := range t.Ports {
		nodes = append(nodes, node)
		collectAllChildren(&nodes, node)
	}
	for _, node := range t.Vhosts {
		nodes = append(nodes, node)
		collectAllChildren(&nodes, node)
	}
	return nodes
}

func collectAllChildren(nodes *[]*ReconNode, node *ReconNode) {
	for _, child := range node.Children {
		*nodes = append(*nodes, child)
		collectAllChildren(nodes, child)
	}
}
