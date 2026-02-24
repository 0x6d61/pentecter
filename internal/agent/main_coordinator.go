package agent

import (
	"context"
	"fmt"
	"strings"
)

// MainCoordinatorConfig は MainCoordinator の構築パラメーター。
type MainCoordinatorConfig struct {
	TargetID     int
	TargetHost   string
	DomainEvents <-chan DomainEvent
	Events       chan<- Event
	ReconRunner  *ReconRunner
	AttackData   *AttackDataTree
	TaskMgr      *TaskManager
}

// MainCoordinator はドメインイベントを受け取り、ルールベースで専門エージェントへ委譲する。
// 注意: これは段階的移行用の最小実装で、既存 Loop と並行稼働する。
type MainCoordinator struct {
	targetID        int
	targetHost      string
	domainEvents    <-chan DomainEvent
	events          chan<- Event
	reconRunner     *ReconRunner
	attackData      *AttackDataTree
	taskMgr         *TaskManager
	deferredHTTP    map[int]struct{}
	webAttackByPort map[int]string
	attackByPort    map[int]string
}

// NewMainCoordinator は MainCoordinator を構築する。
func NewMainCoordinator(cfg MainCoordinatorConfig) *MainCoordinator {
	return &MainCoordinator{
		targetID:        cfg.TargetID,
		targetHost:      cfg.TargetHost,
		domainEvents:    cfg.DomainEvents,
		events:          cfg.Events,
		reconRunner:     cfg.ReconRunner,
		attackData:      cfg.AttackData,
		taskMgr:         cfg.TaskMgr,
		deferredHTTP:    make(map[int]struct{}),
		webAttackByPort: make(map[int]string),
		attackByPort:    make(map[int]string),
	}
}

// Run はドメインイベントループを実行する。
func (mc *MainCoordinator) Run(ctx context.Context) {
	if mc == nil || mc.domainEvents == nil {
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case evt, ok := <-mc.domainEvents:
			if !ok {
				return
			}
			mc.handle(ctx, evt)
		}
	}
}

func (mc *MainCoordinator) handle(ctx context.Context, evt DomainEvent) {
	switch e := evt.(type) {
	case PortDiscovered:
		mc.handlePortDiscovered(ctx, e)
	case ServiceIdentified:
		mc.handleServiceIdentified(ctx, e)
	case WebReconComplete:
		mc.emitLog(fmt.Sprintf("MainCoordinator received WebReconComplete %s:%d (endpoints=%d params=%d vhosts=%d)",
			e.Host, e.Port, len(e.Endpoints), len(e.Params), len(e.Vhosts)))
		mc.retryDeferredHTTP(ctx)
		mc.handleWebReconComplete(ctx, e)
	case AgentComplete:
		if e.AgentType == string(AgentKindWebRecon) {
			mc.retryDeferredHTTP(ctx)
		} else if e.AgentType == string(AgentKindWebAttack) {
			if port, cleared := mc.clearWebAttackByTaskID(e.AgentID); cleared {
				mc.emitLog(fmt.Sprintf("MainCoordinator cleared WebAttackAgent slot for %s:%d (%s)", mc.targetHost, port, e.AgentID))
			}
		} else if e.AgentType == string(AgentKindAttack) {
			if port, cleared := mc.clearAttackByTaskID(e.AgentID); cleared {
				mc.emitLog(fmt.Sprintf("MainCoordinator cleared AttackAgent slot for %s:%d (%s)", mc.targetHost, port, e.AgentID))
			}
		}
	case ReconComplete:
		mc.emitLog(fmt.Sprintf("MainCoordinator received ReconComplete %s (ports=%d)", e.Host, len(e.Ports)))
	}
}

func (mc *MainCoordinator) handlePortDiscovered(ctx context.Context, evt PortDiscovered) {
	if !isHTTPService(evt.Service) {
		return
	}
	if mc.reconRunner == nil || mc.attackData == nil {
		mc.emitLog(fmt.Sprintf("MainCoordinator skip HTTP routing for %s:%d (recon runner unavailable)", evt.Host, evt.Port))
		return
	}
	portNode := mc.attackData.FindPortNode(evt.Port)
	if portNode == nil {
		mc.emitLog(fmt.Sprintf("MainCoordinator skip HTTP routing for %s:%d (port node missing)", evt.Host, evt.Port))
		return
	}
	switch mc.reconRunner.TrySpawnWebReconForPort(ctx, portNode) {
	case ReconSpawnStarted:
		delete(mc.deferredHTTP, evt.Port)
		mc.emitLog(fmt.Sprintf("MainCoordinator routed HTTP port %s:%d (%s) -> WebReconAgent", evt.Host, evt.Port, evt.Service))
	case ReconSpawnDeferredMaxParallel:
		mc.deferredHTTP[evt.Port] = struct{}{}
		mc.emitLog(fmt.Sprintf("MainCoordinator deferred HTTP port %s:%d (%s): waiting for free recon slot", evt.Host, evt.Port, evt.Service))
	case ReconSpawnNoPending:
		delete(mc.deferredHTTP, evt.Port)
	case ReconSpawnFailed:
		delete(mc.deferredHTTP, evt.Port)
		mc.emitLog(fmt.Sprintf("MainCoordinator failed to route HTTP port %s:%d (%s)", evt.Host, evt.Port, evt.Service))
	}
}

func (mc *MainCoordinator) retryDeferredHTTP(ctx context.Context) {
	if len(mc.deferredHTTP) == 0 || mc.reconRunner == nil || mc.attackData == nil {
		return
	}
	for port := range mc.deferredHTTP {
		portNode := mc.attackData.FindPortNode(port)
		if portNode == nil {
			delete(mc.deferredHTTP, port)
			continue
		}
		switch mc.reconRunner.TrySpawnWebReconForPort(ctx, portNode) {
		case ReconSpawnStarted:
			delete(mc.deferredHTTP, port)
			mc.emitLog(fmt.Sprintf("MainCoordinator retried deferred HTTP port %s:%d successfully", mc.targetHost, port))
		case ReconSpawnDeferredMaxParallel:
			// keep deferred
		case ReconSpawnNoPending, ReconSpawnFailed:
			delete(mc.deferredHTTP, port)
		}
	}
}

func (mc *MainCoordinator) handleServiceIdentified(ctx context.Context, evt ServiceIdentified) {
	service := strings.TrimSpace(evt.Service)
	if evt.Port <= 0 || service == "" || isHTTPService(service) {
		return
	}
	if mc.taskMgr == nil || !mc.taskMgr.CanSpawnSmart() {
		mc.emitLog(fmt.Sprintf("MainCoordinator skip AttackAgent for %s:%d (%s): TaskManager/subBrain unavailable",
			evt.Host, evt.Port, evt.Service))
		return
	}
	if _, exists := mc.attackByPort[evt.Port]; exists {
		mc.emitLog(fmt.Sprintf("MainCoordinator skip AttackAgent for %s:%d (%s): already spawned",
			evt.Host, evt.Port, evt.Service))
		return
	}

	host := evt.Host
	if host == "" {
		host = mc.targetHost
	}
	goal := fmt.Sprintf("Infrastructure attack assessment on %s:%d (%s)", host, evt.Port, evt.Service)
	taskID, err := mc.taskMgr.SpawnTask(ctx, SpawnTaskRequest{
		Kind:           TaskKindSmart,
		Goal:           goal,
		Command:        buildAttackPrompt(host, evt),
		TargetHost:     host,
		TargetID:       mc.targetID,
		MaxTurns:       30,
		AttackDataTree: mc.attackData,
		AgentKind:      AgentKindAttack,
		Metadata: TaskMetadata{
			Port:    evt.Port,
			Service: service,
			Phase:   "attack",
		},
	})
	if err != nil {
		mc.emitLog(fmt.Sprintf("MainCoordinator failed to route ServiceIdentified %s:%d (%s) -> AttackAgent: %v",
			host, evt.Port, evt.Service, err))
		return
	}

	mc.attackByPort[evt.Port] = taskID
	mc.emitSubTaskStart(taskID, goal, AgentKindAttack)
	mc.emitLog(fmt.Sprintf("MainCoordinator routed ServiceIdentified %s:%d (%s) -> AttackAgent (%s)",
		host, evt.Port, evt.Service, taskID))
}

func (mc *MainCoordinator) handleWebReconComplete(ctx context.Context, evt WebReconComplete) {
	if evt.Port <= 0 {
		return
	}
	if mc.taskMgr == nil || !mc.taskMgr.CanSpawnSmart() {
		mc.emitLog(fmt.Sprintf("MainCoordinator skip WebAttackAgent for %s:%d (TaskManager/subBrain unavailable)", evt.Host, evt.Port))
		return
	}
	if _, exists := mc.webAttackByPort[evt.Port]; exists {
		mc.emitLog(fmt.Sprintf("MainCoordinator skip WebAttackAgent for %s:%d (already spawned)", evt.Host, evt.Port))
		return
	}

	host := evt.Host
	if host == "" {
		host = mc.targetHost
	}
	service := "http"
	if mc.attackData != nil {
		if node := mc.attackData.FindPortNode(evt.Port); node != nil && node.Service != "" {
			service = node.Service
		}
	}

	goal := fmt.Sprintf("Web vulnerability assessment on %s:%d", host, evt.Port)
	taskID, err := mc.taskMgr.SpawnTask(ctx, SpawnTaskRequest{
		Kind:           TaskKindSmart,
		Goal:           goal,
		Command:        buildWebAttackPrompt(host, evt.Port, evt.Endpoints, evt.Params, evt.Vhosts),
		TargetHost:     host,
		TargetID:       mc.targetID,
		MaxTurns:       30,
		AttackDataTree: mc.attackData,
		AgentKind:      AgentKindWebAttack,
		Metadata: TaskMetadata{
			Port:    evt.Port,
			Service: service,
			Phase:   "web_attack",
		},
	})
	if err != nil {
		mc.emitLog(fmt.Sprintf("MainCoordinator failed to route WebReconComplete %s:%d -> WebAttackAgent: %v", host, evt.Port, err))
		return
	}

	mc.webAttackByPort[evt.Port] = taskID
	mc.emitSubTaskStart(taskID, goal, AgentKindWebAttack)
	mc.emitLog(fmt.Sprintf("MainCoordinator routed WebReconComplete %s:%d -> WebAttackAgent (%s)", host, evt.Port, taskID))
}

func (mc *MainCoordinator) emitLog(msg string) {
	if mc.events == nil {
		return
	}
	select {
	case mc.events <- Event{
		TargetID: mc.targetID,
		Type:     EventLog,
		Source:   SourceSystem,
		Message:  msg,
	}:
	default:
	}
}

func (mc *MainCoordinator) emitSubTaskStart(taskID, message string, kind AgentKind) {
	if mc.events == nil {
		return
	}
	select {
	case mc.events <- Event{
		TargetID:  mc.targetID,
		Type:      EventSubTaskStart,
		TaskID:    taskID,
		Message:   message,
		AgentKind: kind,
	}:
	default:
	}
}

func (mc *MainCoordinator) clearWebAttackByTaskID(taskID string) (port int, cleared bool) {
	for p, id := range mc.webAttackByPort {
		if id == taskID {
			delete(mc.webAttackByPort, p)
			return p, true
		}
	}
	return 0, false
}

func (mc *MainCoordinator) clearAttackByTaskID(taskID string) (port int, cleared bool) {
	for p, id := range mc.attackByPort {
		if id == taskID {
			delete(mc.attackByPort, p)
			return p, true
		}
	}
	return 0, false
}

func buildWebAttackPrompt(host string, port int, endpoints []EndpointInfo, params []ParamInfo, vhosts []string) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "You are a WebAttackAgent for %s:%d.\n", host, port)
	sb.WriteString("Focus on targeted vulnerability validation using discovered attack surface.\n")
	sb.WriteString("Do NOT run broad web reconnaissance tools (webfuzz dir/vhost, dirb, gobuster, nikto).\n")
	sb.WriteString("Use curl/sqlmap/manual payload checks on known endpoints and parameters.\n")
	sb.WriteString("Record important findings with memory action and use complete when work is done.\n\n")

	sb.WriteString("Known endpoints:\n")
	if len(endpoints) == 0 {
		sb.WriteString("- (none)\n")
	} else {
		for _, ep := range endpoints {
			fmt.Fprintf(&sb, "- %s\n", ep.Path)
		}
	}

	sb.WriteString("\nKnown parameters:\n")
	if len(params) == 0 {
		sb.WriteString("- (none)\n")
	} else {
		for _, p := range params {
			fmt.Fprintf(&sb, "- %s (%s) on %s\n", p.Name, p.ParamType, p.Path)
		}
	}

	sb.WriteString("\nKnown virtual hosts:\n")
	if len(vhosts) == 0 {
		sb.WriteString("- (none)\n")
	} else {
		for _, vhost := range vhosts {
			fmt.Fprintf(&sb, "- %s\n", vhost)
		}
	}

	sb.WriteString("\nPrioritize high-value checks first: auth bypass, SQLi, command injection, path traversal, IDOR.\n")
	sb.WriteString("Avoid repeated identical commands when previous attempts had no signal.\n")

	return sb.String()
}

func buildAttackPrompt(host string, evt ServiceIdentified) string {
	service := evt.Service
	if service == "" {
		service = "unknown"
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "You are an AttackAgent for non-HTTP service %s:%d (%s).\n", host, evt.Port, service)
	sb.WriteString("Focus on service-specific validation and exploitation steps only for this port.\n")
	sb.WriteString("Do NOT run broad web reconnaissance tools (webfuzz dir/vhost, dirb, gobuster, nikto).\n")
	sb.WriteString("Use memory action for important findings (credentials, vulnerabilities, access level), then complete.\n\n")

	sb.WriteString("Known CVEs:\n")
	if len(evt.CVEs) == 0 {
		sb.WriteString("- (none)\n")
	} else {
		for _, cve := range evt.CVEs {
			fmt.Fprintf(&sb, "- %s\n", cve)
		}
	}

	sb.WriteString("\nKnown attack vectors:\n")
	if len(evt.AttackVectors) == 0 {
		sb.WriteString("- (none)\n")
	} else {
		for _, v := range evt.AttackVectors {
			fmt.Fprintf(&sb, "- %s\n", v)
		}
	}

	if evt.Notes != "" {
		sb.WriteString("\nRecon notes:\n")
		sb.WriteString(evt.Notes)
		sb.WriteString("\n")
	}

	sb.WriteString("\nPrioritize: known CVE validation -> authentication weaknesses -> misconfiguration abuse.\n")
	return sb.String()
}

func isHTTPService(service string) bool {
	switch strings.ToLower(service) {
	case "http", "https", "http-proxy", "https-alt":
		return true
	default:
		return false
	}
}
