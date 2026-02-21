package agent

import (
	"fmt"
	"strings"
	"sync"
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

// Finding はバリューファジングで発見された脆弱性の疑い
type Finding struct {
	Param    string // パラメーター名 (e.g. "id")
	Category string // ファジングカテゴリ (e.g. "sqli")
	Evidence string // 証拠 (e.g. "500 + MySQL syntax error on single quote")
	Severity string // 深刻度: "high", "medium", "low", "info"
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

	Findings []Finding

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
	mu          sync.RWMutex
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
// 同じポート番号が既に存在する場合は banner/service を更新し、重複追加しない。
func (t *ReconTree) AddPort(port int, service, banner string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	// 重複チェック
	for _, existing := range t.Ports {
		if existing.Port == port {
			// banner/service を更新（より詳しい情報で上書き）
			if banner != "" && len(banner) > len(existing.Banner) {
				existing.Banner = banner
			}
			if service != "" {
				existing.Service = service
			}
			return
		}
	}
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
	t.mu.Lock()
	defer t.mu.Unlock()
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
	t.mu.Lock()
	defer t.mu.Unlock()
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
	t.mu.Lock()
	defer t.mu.Unlock()
	node := t.findNode(host, port, path)
	if node == nil {
		return
	}
	node.setReconStatus(taskType, StatusComplete)
}

// HasPending はツリーに pending タスクがあるか
func (t *ReconTree) HasPending() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.countPendingLocked() > 0
}

// CountPending は pending タスクの総数
func (t *ReconTree) CountPending() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.countPendingLocked()
}

func (t *ReconTree) countPendingLocked() int {
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
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.countCompleteLocked()
}

func (t *ReconTree) countCompleteLocked() int {
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
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.countTotalLocked()
}

func (t *ReconTree) countTotalLocked() int {
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
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.locked && t.countTotalLocked() > 0 && t.countPendingLocked() == 0 {
		t.locked = false
	}
	return t.locked
}

// Unlock は RECON フェーズロックを手動解除する。
func (t *ReconTree) Unlock() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.locked = false
}

// NextBatch は MaxParallel - active 個の pending タスクを優先順で返す。
// 優先順: endpoint_enum > param_fuzz > profiling > vhost_discovery
func (t *ReconTree) NextBatch() []*ReconTask {
	t.mu.RLock()
	defer t.mu.RUnlock()
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
	t.mu.Lock()
	defer t.mu.Unlock()
	task.Node.setReconStatus(task.Type, StatusInProgress)
	t.active++
}

// FinishTask はタスクを完了にし、active カウントを減らす
func (t *ReconTree) FinishTask(task *ReconTask) {
	t.mu.Lock()
	defer t.mu.Unlock()
	task.Node.setReconStatus(task.Type, StatusComplete)
	if t.active > 0 {
		t.active--
	}
}

// CompleteAllPortTasks は指定ポートの InProgress な全タスクを Complete にする。
// SubAgent がポート単位で全 recon を担当するため、完了時に一括で更新する。
// active カウントは SubAgent 単位で管理するため -1 のみ。
func (t *ReconTree) CompleteAllPortTasks(port int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	found := false
	for _, node := range t.Ports {
		if node.Port == port {
			for _, tt := range []ReconTaskType{TaskEndpointEnum, TaskParamFuzz, TaskProfiling, TaskVhostDiscov} {
				if node.getReconStatus(tt) == StatusInProgress {
					node.setReconStatus(tt, StatusComplete)
					found = true
				}
			}
		}
	}
	// SubAgent 単位で -1（タスクタイプ数ではない）
	if found && t.active > 0 {
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

// AddFinding はエンドポイントノードに finding を追加する。
// ノードが見つからない場合は何もしない。
func (t *ReconTree) AddFinding(host string, port int, path string, finding Finding) {
	t.mu.Lock()
	defer t.mu.Unlock()
	node := t.findNode(host, port, path)
	if node == nil {
		return
	}
	node.Findings = append(node.Findings, finding)
}

// CountFindings は全ノードの finding 数を返す
func (t *ReconTree) CountFindings() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	count := 0
	for _, node := range t.allNodes() {
		count += len(node.Findings)
	}
	return count
}

// RenderTree は ASCII ツリーを返す（/recontree 用）
func (t *ReconTree) RenderTree() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
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
	complete := t.countCompleteLocked()
	total := t.countTotalLocked()
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

	// findings + children の合計で最終要素を判定
	totalItems := len(node.Findings) + len(node.Children)
	itemIdx := 0

	for _, f := range node.Findings {
		itemIdx++
		isLast := itemIdx == totalItems
		fp := childPrefix + "|-- "
		if isLast {
			fp = childPrefix + "+-- "
		}
		fmt.Fprintf(sb, "%sfinding: param \"%s\" \u2014 %s (%s)\n", fp, f.Param, f.Category, f.Evidence)
	}

	for _, child := range node.Children {
		itemIdx++
		isLast := itemIdx == totalItems
		cp := childPrefix + "|-- "
		ccp := childPrefix + "|   "
		if isLast {
			cp = childPrefix + "+-- "
			ccp = childPrefix + "    "
		}
		renderEndpointNode(sb, child, cp, ccp)
	}
}

// RenderIntel は RECON INTEL をプロンプト注入用に返す。
// ポートがない場合は空文字列を返す。
func (t *ReconTree) RenderIntel() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if len(t.Ports) == 0 && len(t.Vhosts) == 0 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("=== RECON INTEL ===\n")

	// [BACKGROUND]: InProgress タスクがあるポートを表示
	var activePorts []string
	for _, node := range t.Ports {
		if node.isHTTP() {
			for _, tt := range []ReconTaskType{TaskEndpointEnum, TaskParamFuzz, TaskProfiling, TaskVhostDiscov} {
				if node.getReconStatus(tt) == StatusInProgress {
					activePorts = append(activePorts, fmt.Sprintf("%d", node.Port))
					break
				}
			}
		}
	}
	if len(activePorts) > 0 {
		fmt.Fprintf(&sb, "[BACKGROUND] HTTPAgent active on ports: %s — do NOT run ffuf/dirb yourself\n\n",
			strings.Join(activePorts, ", "))
	}

	// [FINDINGS]: 全ノードの findings を表示
	hasFindings := false
	for _, node := range t.Ports {
		t.renderNodeFindings(&sb, node, &hasFindings)
	}
	for _, node := range t.Vhosts {
		t.renderNodeFindings(&sb, node, &hasFindings)
	}
	if hasFindings {
		sb.WriteString("\n")
	}

	// [ATTACK SURFACE]: 全ポート + ステータス
	sb.WriteString("[ATTACK SURFACE]\n")
	for _, node := range t.Ports {
		status := "not tested"
		if node.isHTTP() {
			// Check if any task is InProgress
			for _, tt := range []ReconTaskType{TaskEndpointEnum, TaskParamFuzz, TaskProfiling, TaskVhostDiscov} {
				if node.getReconStatus(tt) == StatusInProgress {
					status = "HTTPAgent active"
					break
				}
			}
			if status == "not tested" {
				// Check if all tasks are complete
				allComplete := true
				anyTask := false
				for _, tt := range []ReconTaskType{TaskEndpointEnum, TaskParamFuzz, TaskProfiling, TaskVhostDiscov} {
					st := node.getReconStatus(tt)
					if st != StatusNone {
						anyTask = true
						if st != StatusComplete {
							allComplete = false
						}
					}
				}
				if anyTask && allComplete {
					status = "recon complete"
				} else if anyTask {
					status = "recon pending"
				}
			}
		}
		banner := node.Banner
		if banner != "" {
			banner = " " + banner
		}
		fmt.Fprintf(&sb, "  %d/%s%s — %s\n", node.Port, node.Service, banner, status)
	}

	return sb.String()
}

// renderNodeFindings はノードとその子の findings を再帰的にレンダリングする。
func (t *ReconTree) renderNodeFindings(sb *strings.Builder, node *ReconNode, hasFindings *bool) {
	if len(node.Findings) > 0 {
		if !*hasFindings {
			sb.WriteString("[FINDINGS]\n")
			*hasFindings = true
		}
		for _, f := range node.Findings {
			path := node.Path
			if path == "" {
				path = "/"
			}
			fmt.Fprintf(sb, "  Port %d: %s — %s on %s (%s)\n", node.Port, path, f.Category, f.Param, f.Severity)
		}
	}
	for _, child := range node.Children {
		t.renderNodeFindings(sb, child, hasFindings)
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

// SetReconStatusForTest はテスト用エクスポートヘルパー（外部パッケージからステータス設定用）。
func (n *ReconNode) SetReconStatusForTest(taskType ReconTaskType, status ReconStatus) {
	n.setReconStatus(taskType, status)
}

// SetActiveForTest はテスト用エクスポートヘルパー（外部パッケージから active 設定用）。
func (t *ReconTree) SetActiveForTest(n int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.active = n
}

// PortCount はポート数を返す（ロック付き）。
func (t *ReconTree) PortCount() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.Ports)
}

// NewHTTPPortsSince は index 以降の新規 HTTP ポートを返す。
func (t *ReconTree) NewHTTPPortsSince(startIdx int) []*ReconNode {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if startIdx >= len(t.Ports) {
		return nil
	}
	var result []*ReconNode
	for _, port := range t.Ports[startIdx:] {
		if port.isHTTP() && port.EndpointEnum == StatusPending {
			result = append(result, port)
		}
	}
	return result
}

// StartPortRecon は max_parallel チェック + Pending タスクの InProgress マークを原子的に行う。
// spawn 可能なら true を返し active を +1、不可なら false を返す。
func (t *ReconTree) StartPortRecon(port *ReconNode) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.active >= t.MaxParallel {
		return false
	}
	for _, tt := range []ReconTaskType{TaskEndpointEnum, TaskParamFuzz, TaskProfiling, TaskVhostDiscov} {
		if port.getReconStatus(tt) == StatusPending {
			port.setReconStatus(tt, StatusInProgress)
		}
	}
	t.active++
	return true
}

// Active は現在の active カウントを返す（TUI 表示用）。
func (t *ReconTree) Active() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.active
}

func collectAllChildren(nodes *[]*ReconNode, node *ReconNode) {
	for _, child := range node.Children {
		*nodes = append(*nodes, child)
		collectAllChildren(nodes, child)
	}
}
