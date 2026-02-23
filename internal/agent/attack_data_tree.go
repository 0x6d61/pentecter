package agent

import (
	"fmt"
	"path"
	"strings"
	"sync"
)

// AttackDataStatus は偵察タスクの状態
type AttackDataStatus int

const (
	// StatusNone はタスクが存在しない（非 HTTP ポート等）
	StatusNone AttackDataStatus = iota
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
	TaskValueFuzz
	TaskProfiling
	TaskVhostDiscov
)

func (t ReconTaskType) String() string {
	switch t {
	case TaskEndpointEnum:
		return "endpoint_enum"
	case TaskParamFuzz:
		return "param_fuzz"
	case TaskValueFuzz:
		return "value_fuzz"
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
	Param    string `json:"param"`    // パラメーター名 (e.g. "id")
	Category string `json:"category"` // ファジングカテゴリ (e.g. "sqli")
	Evidence string `json:"evidence"` // 証拠 (e.g. "500 + MySQL syntax error on single quote")
	Severity string `json:"severity"` // 深刻度: "high", "medium", "low", "info"
}

// TaskProgress は特定タスクタイプの進捗
type TaskProgress struct {
	Done         int
	Total        int
	PendingPaths []string // このタスクタイプが Pending のパス一覧（最大 maxPendingPaths 件）
}

// ReconProgress は HTTP 偵察の全体進捗
type ReconProgress struct {
	EndpointEnum TaskProgress
	ParamFuzz    TaskProgress
	ValueFuzz    TaskProgress
	Profiling    TaskProgress
	VhostDiscov  TaskProgress
}

// AttackDataNode はツリーの各ノード
type AttackDataNode struct {
	Host    string // "10.10.11.100" or "dev.example.com" (vhost)
	Port    int    // 80, 443, 22... (0 = endpoint node)
	Service string // "http", "ssh", "smb"
	Banner  string // "Apache 2.4.49", "OpenSSH 8.2"
	Path    string // "/", "/api", "/api/v1" (endpoint nodes only)

	// タスクステータス（ノードタイプによって使うフィールドが異なる）
	EndpointEnum AttackDataStatus
	ParamFuzz    AttackDataStatus
	ValueFuzz    AttackDataStatus
	Profiling    AttackDataStatus
	VhostDiscov  AttackDataStatus

	Findings []Finding
	Checklist *ServiceChecklist

	Children []*AttackDataNode
}

// isHTTP は HTTP/HTTPS サービスかどうか
func (n *AttackDataNode) isHTTP() bool {
	return n.Service == "http" || n.Service == "https" ||
		n.Service == "http-proxy" || n.Service == "https-alt"
}

// getAttackDataStatus は指定タスクタイプのステータスを返す
func (n *AttackDataNode) getAttackDataStatus(taskType ReconTaskType) AttackDataStatus {
	switch taskType {
	case TaskEndpointEnum:
		return n.EndpointEnum
	case TaskParamFuzz:
		return n.ParamFuzz
	case TaskValueFuzz:
		return n.ValueFuzz
	case TaskProfiling:
		return n.Profiling
	case TaskVhostDiscov:
		return n.VhostDiscov
	default:
		return StatusNone
	}
}

// setAttackDataStatus は指定タスクタイプのステータスを設定する
func (n *AttackDataNode) setAttackDataStatus(taskType ReconTaskType, status AttackDataStatus) {
	switch taskType {
	case TaskEndpointEnum:
		n.EndpointEnum = status
	case TaskParamFuzz:
		n.ParamFuzz = status
	case TaskValueFuzz:
		n.ValueFuzz = status
	case TaskProfiling:
		n.Profiling = status
	case TaskVhostDiscov:
		n.VhostDiscov = status
	}
}

// countTasks はノードとその子孫の pending/complete/total を再帰的に数える
func (n *AttackDataNode) countTasks() (pending, complete, total int) {
	for _, st := range []AttackDataStatus{n.EndpointEnum, n.ParamFuzz, n.ValueFuzz, n.Profiling, n.VhostDiscov} {
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
	Node *AttackDataNode
	Host string
	Port int
	Path string
}

// AttackDataTree はターゲットの偵察状態を管理するツリー
type AttackDataTree struct {
	mu          sync.RWMutex
	Host        string
	MaxParallel int
	MaxDepth    int          // 0 = unlimited (constructor defaults to 3)
	active      int
	locked      bool         // RECON フェーズがロック中か（true = pending タスク完了まで遷移不可）
	Ports       []*AttackDataNode // ポートレベルノード
	Vhosts      []*AttackDataNode // vhost ルートノード
}

// NewAttackDataTree は新しい AttackDataTree を作成する。maxParallel が 0 ならデフォルト 2、maxDepth が 0 ならデフォルト 3。
func NewAttackDataTree(host string, maxParallel, maxDepth int) *AttackDataTree {
	if maxParallel <= 0 {
		maxParallel = 2
	}
	if maxDepth <= 0 {
		maxDepth = 3
	}
	return &AttackDataTree{
		Host:        host,
		MaxParallel: maxParallel,
		MaxDepth:    maxDepth,
		locked:      true,
	}
}

// pathDepth はパスの深度を返す。
// "/" → 0, "/api" → 1, "/api/v1" → 2, "/api/v1/users" → 3
func pathDepth(p string) int {
	trimmed := strings.Trim(p, "/")
	if trimmed == "" {
		return 0
	}
	return strings.Count(trimmed, "/") + 1
}

// AddPort は nmap で発見したポートをツリーに追加する。
// HTTP 系なら EndpointEnum + VhostDiscov を pending にする。
// 同じポート番号が既に存在する場合は banner/service を更新し、重複追加しない。
func (t *AttackDataTree) AddPort(port int, service, banner string) {
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
			// 非HTTP→HTTP に変わった場合、偵察タスクを初期化
			if existing.isHTTP() && existing.EndpointEnum == StatusNone {
				existing.EndpointEnum = StatusPending
				existing.VhostDiscov = StatusPending
			}
			return
		}
	}
	node := &AttackDataNode{
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

// staticFileExts は静的ファイルの拡張子セット。ParamFuzz/Profiling をスキップする。
var staticFileExts = map[string]bool{
	".css": true, ".js": true, ".png": true, ".jpg": true,
	".jpeg": true, ".gif": true, ".ico": true, ".svg": true,
	".woff": true, ".woff2": true, ".ttf": true, ".eot": true,
	".pdf": true, ".mp4": true, ".webp": true, ".map": true,
}

// isStaticFileExt は静的ファイル拡張子かどうかを返す。
func isStaticFileExt(ext string) bool {
	return staticFileExts[ext]
}

// AddEndpoint は ffuf で発見した endpoint を親ノードの子として追加する。
// httpStatus=0 として AddEndpointWithStatus に委譲する（後方互換）。
func (t *AttackDataTree) AddEndpoint(host string, port int, parentPath, newPath string) {
	t.AddEndpointWithStatus(host, port, parentPath, newPath, 0)
}

// AddEndpointWithStatus は ffuf で発見した endpoint を HTTP ステータスコード付きで追加する。
// ステータスコードに応じてタスクの初期状態を決定する:
//   - 200 or 0（不明）: EndpointEnum + ParamFuzz + Profiling = Pending（フルスキャン対象）
//   - 301/302（リダイレクト）: EndpointEnum = Pending（ディレクトリ列挙対象）、ParamFuzz/Profiling = None
//   - その他（401, 403, 500 等）: 全て StatusNone（スキャン不要）
//
// ファイル拡張子を持つパスは EndpointEnum を StatusNone にする（ディレクトリ列挙不要）。
// MaxDepth を超えるパスも EndpointEnum を StatusNone にする。
func (t *AttackDataTree) AddEndpointWithStatus(host string, port int, parentPath, newPath string, httpStatus int) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Trailing slash 正規化: "/controllers/" → "/controllers"（ルート "/" は除く）
	if len(newPath) > 1 {
		newPath = strings.TrimRight(newPath, "/")
	}

	parent := t.findNode(host, port, parentPath)
	if parent == nil {
		return
	}

	// "/" はポートノード（path=""）と重複するのでスキップ
	if matchPath(parent.Path, newPath) {
		return
	}

	// Determine task statuses based on HTTP status code
	endpointEnum := StatusPending
	paramFuzz := StatusPending
	valueFuzz := StatusPending
	profiling := StatusPending

	switch httpStatus {
	case 0, 200:
		// Full recon: all tasks pending
	case 301, 302:
		// Redirect: likely a directory, enumerate but no param_fuzz/value_fuzz/profiling
		paramFuzz = StatusNone
		valueFuzz = StatusNone
		profiling = StatusNone
	default:
		// 401, 403, 500, etc.: no recon tasks
		endpointEnum = StatusNone
		paramFuzz = StatusNone
		valueFuzz = StatusNone
		profiling = StatusNone
	}

	// 重複チェック: 同じパスが既に存在する場合はスキップ
	for _, existing := range parent.Children {
		if existing.Path == newPath {
			return
		}
	}

	// File extension check: files with extensions don't need directory enumeration
	ext := strings.ToLower(path.Ext(newPath))
	if endpointEnum != StatusNone && ext != "" {
		endpointEnum = StatusNone
	}

	// Static file check: known static extensions skip ParamFuzz/ValueFuzz/Profiling too
	if paramFuzz != StatusNone && isStaticFileExt(ext) {
		paramFuzz = StatusNone
		valueFuzz = StatusNone
		profiling = StatusNone
	}

	// Depth check: if beyond MaxDepth, skip directory enumeration
	if endpointEnum != StatusNone && t.MaxDepth > 0 && pathDepth(newPath) > t.MaxDepth {
		endpointEnum = StatusNone
	}

	child := &AttackDataNode{
		Host:         host,
		Port:         port,
		Path:         newPath,
		EndpointEnum: endpointEnum,
		ParamFuzz:    paramFuzz,
		ValueFuzz:    valueFuzz,
		Profiling:    profiling,
	}
	parent.Children = append(parent.Children, child)
}

// AddVhost は ffuf で発見した仮想ホストをツリーに追加する。
// VhostDiscov + EndpointEnum を pending にする。
func (t *AttackDataTree) AddVhost(parentHost string, port int, vhostName string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	node := &AttackDataNode{
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
func (t *AttackDataTree) CompleteTask(host string, port int, path string, taskType ReconTaskType) {
	t.mu.Lock()
	defer t.mu.Unlock()
	node := t.findNode(host, port, path)
	if node == nil {
		return
	}
	node.setAttackDataStatus(taskType, StatusComplete)
}

// HasPending はツリーに pending タスクがあるか
func (t *AttackDataTree) HasPending() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.countPendingLocked() > 0
}

// CountPending は pending タスクの総数
func (t *AttackDataTree) CountPending() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.countPendingLocked()
}

func (t *AttackDataTree) countPendingLocked() int {
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
func (t *AttackDataTree) CountComplete() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.countCompleteLocked()
}

func (t *AttackDataTree) countCompleteLocked() int {
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
func (t *AttackDataTree) CountTotal() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.countTotalLocked()
}

func (t *AttackDataTree) countTotalLocked() int {
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
func (t *AttackDataTree) IsLocked() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.locked && t.countTotalLocked() > 0 && t.countPendingLocked() == 0 {
		t.locked = false
	}
	return t.locked
}

// Unlock は RECON フェーズロックを手動解除する。
func (t *AttackDataTree) Unlock() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.locked = false
}

// NextBatch は MaxParallel - active 個の pending タスクを優先順で返す。
// 優先順: endpoint_enum > param_fuzz > profiling > vhost_discovery
func (t *AttackDataTree) NextBatch() []*ReconTask {
	t.mu.RLock()
	defer t.mu.RUnlock()
	available := t.MaxParallel - t.active
	if available <= 0 {
		return nil
	}

	var tasks []*ReconTask
	// 優先順にタスクを収集
	for _, taskType := range []ReconTaskType{TaskEndpointEnum, TaskParamFuzz, TaskValueFuzz, TaskProfiling, TaskVhostDiscov} {
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
func (t *AttackDataTree) collectPending(tasks *[]*ReconTask, taskType ReconTaskType, limit int) {
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

func (t *AttackDataTree) collectPendingFromNode(tasks *[]*ReconTask, node *AttackDataNode, taskType ReconTaskType, limit int) {
	if len(*tasks) >= limit {
		return
	}
	if node.getAttackDataStatus(taskType) == StatusPending {
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
func (t *AttackDataTree) StartTask(task *ReconTask) {
	t.mu.Lock()
	defer t.mu.Unlock()
	task.Node.setAttackDataStatus(task.Type, StatusInProgress)
	t.active++
}

// FinishTask はタスクを完了にし、active カウントを減らす
func (t *AttackDataTree) FinishTask(task *ReconTask) {
	t.mu.Lock()
	defer t.mu.Unlock()
	task.Node.setAttackDataStatus(task.Type, StatusComplete)
	if t.active > 0 {
		t.active--
	}
}

// CompleteAllPortTasks は指定ポートの InProgress な全タスクを Complete にする。
// SubAgent がポート単位で全 recon を担当するため、完了時に一括で更新する。
// active カウントは SubAgent 単位で管理するため -1 のみ。
func (t *AttackDataTree) CompleteAllPortTasks(port int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	found := false
	for _, node := range t.Ports {
		if node.Port == port {
			for _, tt := range []ReconTaskType{TaskEndpointEnum, TaskParamFuzz, TaskValueFuzz, TaskProfiling, TaskVhostDiscov} {
				if node.getAttackDataStatus(tt) == StatusInProgress {
					node.setAttackDataStatus(tt, StatusComplete)
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

// PortHasPendingChildren はポートの子孫ノードに Pending タスクがあるか返す。
// SubAgent が MaxTurns で完了した後、残タスクの有無を判定するために使用する。
func (t *AttackDataTree) PortHasPendingChildren(port int) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	for _, node := range t.Ports {
		if node.Port == port {
			return nodeHasPendingChildren(node)
		}
	}
	return false
}

// nodeHasPendingChildren は子ノードを再帰的に走査し、Pending タスクがあるか返す。
func nodeHasPendingChildren(node *AttackDataNode) bool {
	for _, child := range node.Children {
		for _, st := range []AttackDataStatus{child.EndpointEnum, child.ParamFuzz, child.ValueFuzz, child.Profiling, child.VhostDiscov} {
			if st == StatusPending {
				return true
			}
		}
		if nodeHasPendingChildren(child) {
			return true
		}
	}
	return false
}

// FindPortNode は指定ポート番号のノードを返す。見つからなければ nil。
func (t *AttackDataTree) FindPortNode(port int) *AttackDataNode {
	t.mu.RLock()
	defer t.mu.RUnlock()
	for _, node := range t.Ports {
		if node.Port == port {
			return node
		}
	}
	return nil
}

// findNode はホスト/ポート/パスでノードを検索する。
// path が "/" かつポートノードの Path が "" の場合はポートノード自身を返す（ルート扱い）。
func (t *AttackDataTree) findNode(host string, port int, path string) *AttackDataNode {
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

func findNodeRecursive(node *AttackDataNode, host string, port int, path string) *AttackDataNode {
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
func statusIcon(s AttackDataStatus) string {
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

// statusLabel はステータスの人間可読なラベルを返す。
func statusLabel(s AttackDataStatus) string {
	switch s {
	case StatusComplete:
		return "complete"
	case StatusInProgress:
		return "running"
	case StatusPending:
		return "pending"
	default:
		return ""
	}
}

// taskStatusLine はタスクステータスの1行を返す。StatusNone なら空文字。
func taskStatusLine(name string, s AttackDataStatus) string {
	label := statusLabel(s)
	if label == "" {
		return ""
	}
	return fmt.Sprintf("%s: %s", name, label)
}

// AddFinding はエンドポイントノードに finding を追加する。
// ノードが見つからない場合は何もしない。
func (t *AttackDataTree) AddFinding(host string, port int, path string, finding Finding) {
	t.mu.Lock()
	defer t.mu.Unlock()
	node := t.findNode(host, port, path)
	if node == nil {
		return
	}
	node.Findings = append(node.Findings, finding)
}

// CountFindings は全ノードの finding 数を返す
func (t *AttackDataTree) CountFindings() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	count := 0
	for _, node := range t.allNodes() {
		count += len(node.Findings)
	}
	return count
}

// RenderTree は ASCII ツリーを返す（/attackdata 用）
func (t *AttackDataTree) RenderTree() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	var sb strings.Builder
	sb.WriteString(t.Host)
	sb.WriteString("\n")

	allNodes := make([]*AttackDataNode, 0, len(t.Ports)+len(t.Vhosts))
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

func renderNode(sb *strings.Builder, node *AttackDataNode, prefix, childPrefix string, isVhost bool) {
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

			// endpoint ノードのステータス（ルートレベル）— 新形式で表示
			hasRootTasks := node.EndpointEnum != StatusNone
			if hasRootTasks {
				rootPrefix := childPrefix + "|-- "
				rootChildPrefix := childPrefix + "|   "
				if !hasChildren {
					rootPrefix = childPrefix + "+-- "
					rootChildPrefix = childPrefix + "    "
				}
				// ルートを仮の endpoint ノードとしてレンダリング
				rootNode := &AttackDataNode{
					Path:         "/",
					EndpointEnum: node.EndpointEnum,
					ParamFuzz:    node.ParamFuzz,
					ValueFuzz:    node.ValueFuzz,
					Profiling:    node.Profiling,
				}
				renderEndpointNode(sb, rootNode, rootPrefix, rootChildPrefix)
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

func renderEndpointNode(sb *strings.Builder, node *AttackDataNode, prefix, childPrefix string) {
	fmt.Fprintf(sb, "%s%s\n", prefix, node.Path)

	// タスクステータス行を収集（StatusNone は表示しない）
	var taskLines []string
	for _, pair := range []struct {
		name   string
		status AttackDataStatus
	}{
		{"endpoint_enum", node.EndpointEnum},
		{"param_fuzz", node.ParamFuzz},
		{"value_fuzz", node.ValueFuzz},
		{"profiling", node.Profiling},
	} {
		if line := taskStatusLine(pair.name, pair.status); line != "" {
			taskLines = append(taskLines, line)
		}
	}

	// findings + children + taskLines の合計で最終要素を判定
	totalItems := len(taskLines) + len(node.Findings) + len(node.Children)
	itemIdx := 0

	for _, line := range taskLines {
		itemIdx++
		isLast := itemIdx == totalItems
		tp := childPrefix + "|-- "
		if isLast {
			tp = childPrefix + "+-- "
		}
		fmt.Fprintf(sb, "%s%s\n", tp, line)
	}

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


// SetChecklist sets the recon checklist for a non-HTTP port.
// No-op if the port already has a checklist or if the port is HTTP.
func (t *AttackDataTree) SetChecklist(port int, checklist *ServiceChecklist) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, node := range t.Ports {
		if node.Port == port {
			if node.isHTTP() || node.Checklist != nil {
				return
			}
			node.Checklist = checklist
			return
		}
	}
}

// UpdateAllChecklists updates completion state of all port checklists based on command history.
func (t *AttackDataTree) UpdateAllChecklists(commands []string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, node := range t.Ports {
		if node.Checklist != nil {
			UpdateChecklistCompletion(node.Checklist, commands)
		}
	}
}

// AllChecklistsDone returns true if all non-HTTP ports' checklists are fully complete.
// Returns true if no checklists exist (vacuously true).
func (t *AttackDataTree) AllChecklistsDone() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.allChecklistsDoneLocked()
}

// allChecklistsDoneLocked is a lock-free helper for use within methods that already hold the lock.
func (t *AttackDataTree) allChecklistsDoneLocked() bool {
	for _, node := range t.Ports {
		if node.Checklist != nil && !ChecklistAllDone(node.Checklist) {
			return false
		}
	}
	return true
}


const maxPendingPaths = 10

// ComputeReconProgress は HTTP 偵察のタスクタイプ別進捗を計算する。
func (t *AttackDataTree) ComputeReconProgress() ReconProgress {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.computeReconProgressLocked()
}

func (t *AttackDataTree) computeReconProgressLocked() ReconProgress {
	var prog ReconProgress
	for _, node := range t.Ports {
		if node.isHTTP() {
			t.accumulateProgress(&prog, node)
		}
	}
	for _, node := range t.Vhosts {
		t.accumulateProgress(&prog, node)
	}
	return prog
}

func (t *AttackDataTree) accumulateProgress(prog *ReconProgress, node *AttackDataNode) {
	path := node.Path
	if path == "" {
		path = "/"
	}

	// Count tasks and collect pending paths for each task type
	accumTaskProgressWithPath(&prog.EndpointEnum, node.EndpointEnum, path)
	accumTaskProgressWithPath(&prog.ParamFuzz, node.ParamFuzz, path)
	accumTaskProgressWithPath(&prog.ValueFuzz, node.ValueFuzz, path)
	accumTaskProgressWithPath(&prog.Profiling, node.Profiling, path)
	accumTaskProgressWithPath(&prog.VhostDiscov, node.VhostDiscov, path)

	// Recurse into children
	for _, child := range node.Children {
		t.accumulateProgress(prog, child)
	}
}

func accumTaskProgressWithPath(tp *TaskProgress, status AttackDataStatus, path string) {
	if status == StatusNone {
		return
	}
	tp.Total++
	if status == StatusComplete {
		tp.Done++
	}
	if status == StatusPending && len(tp.PendingPaths) < maxPendingPaths {
		tp.PendingPaths = append(tp.PendingPaths, path)
	}
}

// IsReconComplete は全 Recon が完了したかを判定する。
// HTTP タスク（CountPending==0）+ 非 HTTP チェックリスト（AllChecklistsDone）の両方が完了で true。
// タスクが1つもない場合は false（まだ nmap していない）。
func (t *AttackDataTree) IsReconComplete() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	total := t.countTotalLocked()
	hasChecklist := false
	for _, node := range t.Ports {
		if node.Checklist != nil {
			hasChecklist = true
			break
		}
	}
	// At least some work must exist
	if total == 0 && !hasChecklist {
		return false
	}
	// All HTTP tasks complete
	if t.countPendingLocked() > 0 {
		return false
	}
	// All non-HTTP checklists complete
	if !t.allChecklistsDoneLocked() {
		return false
	}
	return true
}

func renderTaskProgress(sb *strings.Builder, name string, tp TaskProgress) {
	if tp.Total == 0 {
		return
	}
	pct := tp.Done * 100 / tp.Total
	if len(tp.PendingPaths) > 0 {
		fmt.Fprintf(sb, "  %s: %d/%d (%d%%) \u2014 pending: %s\n", name, tp.Done, tp.Total, pct, strings.Join(tp.PendingPaths, ", "))
	} else {
		fmt.Fprintf(sb, "  %s: %d/%d (%d%%)\n", name, tp.Done, tp.Total, pct)
	}
}

// RenderIntel は RECON INTEL をプロンプト注入用に返す。
// ポートがない場合は空文字列を返す。
func (t *AttackDataTree) RenderIntel() string {
	return t.renderIntelInternal(false)
}

// RenderIntelForSubAgent は SubAgent 用の RECON INTEL を返す。
// [BACKGROUND] セクションを除外する（SubAgent 自身が HTTPAgent なので不要）。
func (t *AttackDataTree) RenderIntelForSubAgent() string {
	return t.renderIntelInternal(true)
}

func (t *AttackDataTree) renderIntelInternal(forSubAgent bool) string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if len(t.Ports) == 0 && len(t.Vhosts) == 0 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("=== RECON INTEL ===\n")

	// [BACKGROUND]: Main Agent 向け（SubAgent にはこのセクションを表示しない）
	if !forSubAgent {
		var activePorts []string
		for _, node := range t.Ports {
			if node.isHTTP() {
				for _, tt := range []ReconTaskType{TaskEndpointEnum, TaskParamFuzz, TaskValueFuzz, TaskProfiling, TaskVhostDiscov} {
					if node.getAttackDataStatus(tt) == StatusInProgress {
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
	}



	// [RECON PROGRESS]: HTTP タスクタイプ別進捗
	prog := t.computeReconProgressLocked()
	httpTotal := prog.EndpointEnum.Total + prog.ParamFuzz.Total + prog.ValueFuzz.Total + prog.Profiling.Total + prog.VhostDiscov.Total
	if httpTotal > 0 {
		sb.WriteString("[RECON PROGRESS]\n")
		sb.WriteString("HTTP Recon:\n")
		renderTaskProgress(&sb, "endpoint_enum", prog.EndpointEnum)
		renderTaskProgress(&sb, "param_fuzz", prog.ParamFuzz)
		renderTaskProgress(&sb, "value_fuzz", prog.ValueFuzz)
		renderTaskProgress(&sb, "profiling", prog.Profiling)
		renderTaskProgress(&sb, "vhost_discovery", prog.VhostDiscov)
		httpDone := prog.EndpointEnum.Done + prog.ParamFuzz.Done + prog.ValueFuzz.Done + prog.Profiling.Done + prog.VhostDiscov.Done
		if httpDone == httpTotal {
			sb.WriteString("Overall: COMPLETE — ready for exploitation phase\n")
		} else {
			pct := httpDone * 100 / httpTotal
			fmt.Fprintf(&sb, "Overall: %d/%d tasks (%d%%)\n", httpDone, httpTotal, pct)
		}
		sb.WriteString("\n")
	}

	// [RECON CHECKLIST]: 非HTTPポートのチェックリスト
	hasChecklist := false
	for _, node := range t.Ports {
		if node.Checklist == nil {
			continue
		}
		if !hasChecklist {
			sb.WriteString("[RECON CHECKLIST]\n")
			hasChecklist = true
		}
		banner := node.Banner
		if banner != "" {
			banner = " (" + banner + ")"
		}
		fmt.Fprintf(&sb, "Port %d/%s%s:\n", node.Port, node.Service, banner)
		for _, item := range node.Checklist.Items {
			check := "[ ]"
			if item.Done {
				check = "[x]"
			}
			fmt.Fprintf(&sb, "  %s %s\n", check, item.Description)
		}
		if ChecklistAllDone(node.Checklist) {
			sb.WriteString("  ** ALL ITEMS COMPLETE **\n")
		}
	}
	if hasChecklist && t.allChecklistsDoneLocked() {
		sb.WriteString("ALL NON-HTTP RECON COMPLETE. Use \"wait\" action or proceed to ANALYZE.\n")
	}
	if hasChecklist {
		sb.WriteString("\n")
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
			for _, tt := range []ReconTaskType{TaskEndpointEnum, TaskParamFuzz, TaskValueFuzz, TaskProfiling, TaskVhostDiscov} {
				if node.getAttackDataStatus(tt) == StatusInProgress {
					status = "HTTPAgent active"
					break
				}
			}
			if status == "not tested" {
				_, complete, total := node.countTasks()
				if total > 0 && complete == total {
					status = fmt.Sprintf("recon complete (%d/%d)", complete, total)
				} else if total > 0 {
					status = fmt.Sprintf("recon: %d/%d tasks", complete, total)
				}
			}
		} else if node.Checklist != nil {
			done := 0
			for _, item := range node.Checklist.Items {
				if item.Done {
					done++
				}
			}
			total := len(node.Checklist.Items)
			if done == total {
				status = fmt.Sprintf("recon complete (%d/%d)", done, total)
			} else {
				status = fmt.Sprintf("recon: %d/%d", done, total)
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
func (t *AttackDataTree) renderNodeFindings(sb *strings.Builder, node *AttackDataNode, hasFindings *bool) {
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
func (t *AttackDataTree) allNodes() []*AttackDataNode {
	var nodes []*AttackDataNode
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

// SetAttackDataStatusForTest はテスト用エクスポートヘルパー（外部パッケージからステータス設定用）。
func (n *AttackDataNode) SetAttackDataStatusForTest(taskType ReconTaskType, status AttackDataStatus) {
	n.setAttackDataStatus(taskType, status)
}

// SetActiveForTest はテスト用エクスポートヘルパー（外部パッケージから active 設定用）。
func (t *AttackDataTree) SetActiveForTest(n int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.active = n
}

// PortCount はポート数を返す（ロック付き）。
func (t *AttackDataTree) PortCount() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.Ports)
}

// PendingHTTPPorts は EndpointEnum == StatusPending の全 HTTP ポートを返す。
// 新規追加ポートと、非HTTP→HTTP に更新されたポートの両方を検出する。
func (t *AttackDataTree) PendingHTTPPorts() []*AttackDataNode {
	t.mu.RLock()
	defer t.mu.RUnlock()
	var result []*AttackDataNode
	for _, port := range t.Ports {
		if port.isHTTP() && port.EndpointEnum == StatusPending {
			result = append(result, port)
		}
	}
	return result
}

// NonHTTPPortsWithoutChecklist はチェックリスト未設定の非 HTTP ポートを返す。
func (t *AttackDataTree) NonHTTPPortsWithoutChecklist() []*AttackDataNode {
	t.mu.RLock()
	defer t.mu.RUnlock()
	var result []*AttackDataNode
	for _, port := range t.Ports {
		if !port.isHTTP() && port.Checklist == nil {
			result = append(result, port)
		}
	}
	return result
}

// StartPortRecon は max_parallel チェック + Pending タスクの InProgress マークを原子的に行う。
// spawn 可能なら true を返し active を +1、不可なら false を返す。
func (t *AttackDataTree) StartPortRecon(port *AttackDataNode) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.active >= t.MaxParallel {
		return false
	}
	for _, tt := range []ReconTaskType{TaskEndpointEnum, TaskParamFuzz, TaskValueFuzz, TaskProfiling, TaskVhostDiscov} {
		if port.getAttackDataStatus(tt) == StatusPending {
			port.setAttackDataStatus(tt, StatusInProgress)
		}
	}
	t.active++
	return true
}

// Active は現在の active カウントを返す（TUI 表示用）。
func (t *AttackDataTree) Active() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.active
}

func collectAllChildren(nodes *[]*AttackDataNode, node *AttackDataNode) {
	for _, child := range node.Children {
		*nodes = append(*nodes, child)
		collectAllChildren(nodes, child)
	}
}

// AttackDataSnapshot は AttackDataTree の JSON シリアライズ用構造体
type AttackDataSnapshot struct {
	Host        string              `json:"host"`
	MaxParallel int                 `json:"max_parallel"`
	MaxDepth    int                 `json:"max_depth"`
	Locked      bool                `json:"locked"`
	Ports       []AttackDataNodeDTO `json:"ports"`
	Vhosts      []AttackDataNodeDTO `json:"vhosts"`
}

// AttackDataNodeDTO はノードの JSON 表現
type AttackDataNodeDTO struct {
	Host         string              `json:"host"`
	Port         int                 `json:"port"`
	Service      string              `json:"service"`
	Banner       string              `json:"banner"`
	Path         string              `json:"path"`
	EndpointEnum AttackDataStatus    `json:"endpoint_enum"`
	ParamFuzz    AttackDataStatus    `json:"param_fuzz"`
	ValueFuzz    AttackDataStatus    `json:"value_fuzz"`
	Profiling    AttackDataStatus    `json:"profiling"`
	VhostDiscov  AttackDataStatus    `json:"vhost_discovery"`
	Findings     []Finding           `json:"findings,omitempty"`
	Checklist    *ServiceChecklist   `json:"checklist,omitempty"`
	Children     []AttackDataNodeDTO `json:"children,omitempty"`
}

// Snapshot は現在のツリー状態のスナップショットを返す（スレッドセーフ）。
func (t *AttackDataTree) Snapshot() AttackDataSnapshot {
	t.mu.RLock()
	defer t.mu.RUnlock()
	snap := AttackDataSnapshot{
		Host:        t.Host,
		MaxParallel: t.MaxParallel,
		MaxDepth:    t.MaxDepth,
		Locked:      t.locked,
	}
	for _, node := range t.Ports {
		snap.Ports = append(snap.Ports, nodeToDTO(node))
	}
	for _, node := range t.Vhosts {
		snap.Vhosts = append(snap.Vhosts, nodeToDTO(node))
	}
	return snap
}

// RestoreAttackDataTree はスナップショットから AttackDataTree を復元する。
// InProgress のタスクは Pending にリセットされる（SubAgent は再起動が必要なため）。
// active カウンタは 0 にリセットされる。
func RestoreAttackDataTree(snap AttackDataSnapshot) *AttackDataTree {
	tree := &AttackDataTree{
		Host:        snap.Host,
		MaxParallel: snap.MaxParallel,
		MaxDepth:    snap.MaxDepth,
		locked:      snap.Locked,
		active:      0, // SubAgent は別途再 spawn
	}
	if tree.MaxParallel <= 0 {
		tree.MaxParallel = 2
	}
	if tree.MaxDepth <= 0 {
		tree.MaxDepth = 3
	}
	for _, dto := range snap.Ports {
		tree.Ports = append(tree.Ports, dtoToNode(dto))
	}
	for _, dto := range snap.Vhosts {
		tree.Vhosts = append(tree.Vhosts, dtoToNode(dto))
	}
	return tree
}

// nodeToDTO は AttackDataNode を DTO に変換する。
func nodeToDTO(node *AttackDataNode) AttackDataNodeDTO {
	dto := AttackDataNodeDTO{
		Host:         node.Host,
		Port:         node.Port,
		Service:      node.Service,
		Banner:       node.Banner,
		Path:         node.Path,
		EndpointEnum: node.EndpointEnum,
		ParamFuzz:    node.ParamFuzz,
		ValueFuzz:    node.ValueFuzz,
		Profiling:    node.Profiling,
		VhostDiscov:  node.VhostDiscov,
		Findings:     node.Findings,
		Checklist:    node.Checklist,
	}
	for _, child := range node.Children {
		dto.Children = append(dto.Children, nodeToDTO(child))
	}
	return dto
}

// dtoToNode は DTO から AttackDataNode を復元する。
// InProgress のタスクは Pending にリセットする。
func dtoToNode(dto AttackDataNodeDTO) *AttackDataNode {
	node := &AttackDataNode{
		Host:         dto.Host,
		Port:         dto.Port,
		Service:      dto.Service,
		Banner:       dto.Banner,
		Path:         dto.Path,
		EndpointEnum: resetInProgress(dto.EndpointEnum),
		ParamFuzz:    resetInProgress(dto.ParamFuzz),
		ValueFuzz:    resetInProgress(dto.ValueFuzz),
		Profiling:    resetInProgress(dto.Profiling),
		VhostDiscov:  resetInProgress(dto.VhostDiscov),
		Findings:     dto.Findings,
		Checklist:    dto.Checklist,
	}
	for _, childDTO := range dto.Children {
		node.Children = append(node.Children, dtoToNode(childDTO))
	}
	return node
}

// resetInProgress は InProgress を Pending にリセットする。
func resetInProgress(s AttackDataStatus) AttackDataStatus {
	if s == StatusInProgress {
		return StatusPending
	}
	return s
}
