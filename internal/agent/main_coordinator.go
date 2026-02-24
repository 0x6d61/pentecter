package agent

import (
	"context"
	"fmt"
	"sort"
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
	targetID         int
	targetHost       string
	domainEvents     <-chan DomainEvent
	events           chan<- Event
	reconRunner      *ReconRunner
	attackData       *AttackDataTree
	taskMgr          *TaskManager
	deferredHTTP     map[int]struct{}
	webAttackByPort  map[int]string
	attackByPort     map[int]string
	credentialPivots map[string]struct{}
}

// NewMainCoordinator は MainCoordinator を構築する。
func NewMainCoordinator(cfg MainCoordinatorConfig) *MainCoordinator {
	return &MainCoordinator{
		targetID:         cfg.TargetID,
		targetHost:       cfg.TargetHost,
		domainEvents:     cfg.DomainEvents,
		events:           cfg.Events,
		reconRunner:      cfg.ReconRunner,
		attackData:       cfg.AttackData,
		taskMgr:          cfg.TaskMgr,
		deferredHTTP:     make(map[int]struct{}),
		webAttackByPort:  make(map[int]string),
		attackByPort:     make(map[int]string),
		credentialPivots: make(map[string]struct{}),
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
	case VulnFound:
		mc.handleVulnFound(e)
	case ExploitSuccess:
		mc.handleExploitSuccess(e)
	case CredentialFound:
		mc.handleCredentialFound(ctx, e)
	case AccessGained:
		mc.handleAccessGained(e)
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
	mc.spawnAttackTask(ctx, evt, nil, "service_identified")
}

func (mc *MainCoordinator) handleVulnFound(evt VulnFound) {
	host := evt.Host
	if host == "" {
		host = mc.targetHost
	}
	if mc.attackData != nil {
		treePath := strings.TrimSpace(evt.Path)
		if treePath == "" {
			if node := mc.attackData.FindPortNode(evt.Port); node != nil && isHTTPService(node.Service) {
				treePath = "/"
			}
		}
		mc.attackData.AddFinding(host, evt.Port, treePath, Finding{
			Param:    strings.TrimSpace(evt.Param),
			Category: strings.TrimSpace(evt.VulnType),
			Evidence: strings.TrimSpace(evt.Evidence),
			Severity: strings.TrimSpace(evt.Severity),
		})
		mc.attackData.AddInsight(host, evt.Port, Insight{
			Source: string(evt.Base().AgentKind),
			Topic:  "vuln:" + strings.TrimSpace(evt.VulnType),
			Detail: strings.TrimSpace(evt.Evidence),
		})
	}

	path := strings.TrimSpace(evt.Path)
	if path == "" {
		path = "(service-level)"
	}
	mc.emitLog(fmt.Sprintf("MainCoordinator observed VulnFound %s:%d %s [%s] param=%s",
		host, evt.Port, path, evt.Severity, evt.Param))
}

func (mc *MainCoordinator) handleExploitSuccess(evt ExploitSuccess) {
	host := evt.Host
	if host == "" {
		host = mc.targetHost
	}
	if mc.attackData != nil {
		detail := strings.TrimSpace(evt.Detail)
		if detail == "" {
			detail = strings.TrimSpace(evt.Impact)
		}
		mc.attackData.AddInsight(host, evt.Port, Insight{
			Source: string(evt.Base().AgentKind),
			Topic:  "exploit:" + strings.TrimSpace(evt.VulnType),
			Detail: detail,
		})
	}
	mc.emitLog(fmt.Sprintf("MainCoordinator observed ExploitSuccess %s:%d vuln=%s impact=%s",
		host, evt.Port, evt.VulnType, evt.Impact))
}

func (mc *MainCoordinator) handleCredentialFound(ctx context.Context, evt CredentialFound) {
	host := evt.Host
	if host == "" {
		host = mc.targetHost
	}
	service := strings.TrimSpace(evt.Service)
	if service == "" {
		service = "unknown"
	}
	cred := Credential{
		Service:  service,
		Username: strings.TrimSpace(evt.Username),
		Password: strings.TrimSpace(evt.Password),
		Source:   string(evt.Base().AgentKind),
	}

	if mc.attackData != nil {
		mc.attackData.AddCredential(host, evt.Port, cred)
		mc.attackData.AddInsight(host, evt.Port, Insight{
			Source: string(evt.Base().AgentKind),
			Topic:  "credential_found",
			Detail: fmt.Sprintf("%s %s:%s", service, cred.Username, cred.Password),
		})
	}

	mc.emitLog(fmt.Sprintf("MainCoordinator observed CredentialFound %s:%d %s %s:%s",
		host, evt.Port, service, cred.Username, cred.Password))
	mc.attemptCredentialPivot(ctx, host, evt, cred)
}

func (mc *MainCoordinator) handleAccessGained(evt AccessGained) {
	host := evt.Host
	if host == "" {
		host = mc.targetHost
	}
	service := strings.TrimSpace(evt.Service)
	if service == "" {
		service = "unknown"
	}
	level := strings.TrimSpace(evt.Level)
	if level == "" {
		level = "user"
	}
	if mc.attackData != nil {
		mc.attackData.AddInsight(host, evt.Port, Insight{
			Source: string(evt.Base().AgentKind),
			Topic:  "access_gained",
			Detail: fmt.Sprintf("%s level on %s:%d", level, service, evt.Port),
		})
	}
	mc.emitLog(fmt.Sprintf("MainCoordinator observed AccessGained %s:%d service=%s level=%s",
		host, evt.Port, service, level))
}

func (mc *MainCoordinator) spawnAttackTask(ctx context.Context, evt ServiceIdentified, creds []Credential, reason string) bool {
	service := strings.TrimSpace(evt.Service)
	if evt.Port <= 0 || service == "" || isHTTPService(service) {
		return false
	}

	host := evt.Host
	if host == "" {
		host = mc.targetHost
	}
	if mc.taskMgr == nil || !mc.taskMgr.CanSpawnSmart() {
		mc.emitLog(fmt.Sprintf("MainCoordinator skip AttackAgent for %s:%d (%s): TaskManager/subBrain unavailable",
			host, evt.Port, evt.Service))
		return false
	}
	if _, exists := mc.attackByPort[evt.Port]; exists {
		mc.emitLog(fmt.Sprintf("MainCoordinator skip AttackAgent for %s:%d (%s): already spawned",
			host, evt.Port, evt.Service))
		return false
	}

	goal := fmt.Sprintf("Infrastructure attack assessment on %s:%d (%s)", host, evt.Port, evt.Service)
	if reason == "credential_pivot" {
		goal = fmt.Sprintf("Credential reuse pivot on %s:%d (%s)", host, evt.Port, evt.Service)
	}
	taskID, err := mc.taskMgr.SpawnTask(ctx, SpawnTaskRequest{
		Kind:           TaskKindSmart,
		Goal:           goal,
		Command:        buildAttackPrompt(host, evt, creds),
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
		mc.emitLog(fmt.Sprintf("MainCoordinator failed to route %s %s:%d (%s) -> AttackAgent: %v",
			reason, host, evt.Port, evt.Service, err))
		return false
	}

	mc.attackByPort[evt.Port] = taskID
	mc.emitSubTaskStart(taskID, goal, AgentKindAttack)
	mc.emitLog(fmt.Sprintf("MainCoordinator routed %s %s:%d (%s) -> AttackAgent (%s)",
		reason, host, evt.Port, evt.Service, taskID))
	return true
}

func (mc *MainCoordinator) attemptCredentialPivot(ctx context.Context, host string, origin CredentialFound, cred Credential) {
	if mc.taskMgr == nil || !mc.taskMgr.CanSpawnSmart() || mc.attackData == nil {
		return
	}

	ports := mc.attackData.SnapshotPorts()
	if len(ports) == 0 {
		return
	}
	spawned := 0
	for _, p := range ports {
		service := strings.TrimSpace(p.Service)
		if p.Port <= 0 || p.Port == origin.Port || service == "" || isHTTPService(service) {
			continue
		}
		if _, exists := mc.attackByPort[p.Port]; exists {
			continue
		}

		key := fmt.Sprintf("%s|%d|%d|%s|%s|%s", host, origin.Port, p.Port, service, cred.Username, cred.Password)
		if _, exists := mc.credentialPivots[key]; exists {
			continue
		}

		cves, insightNotes := mc.collectHackTricksIntelForPort(p.Port)
		vectors := []string{"credential reuse validation"}
		if strings.EqualFold(service, cred.Service) {
			vectors = append(vectors, "same-service credential reuse")
		}
		notesParts := []string{
			fmt.Sprintf("Credential found on %d/%s: %s:%s", origin.Port, cred.Service, cred.Username, cred.Password),
			"Try authenticated access first before brute-force checks.",
		}
		if insightNotes != "" {
			notesParts = append(notesParts, "HackTricks insights: "+insightNotes)
		}
		evt := ServiceIdentified{
			DomainEventBase: NewDomainEventBase(mc.targetID, host, AgentKindMain),
			Port:            p.Port,
			Service:         service,
			CVEs:            cves,
			AttackVectors:   vectors,
			Notes:           strings.Join(notesParts, " "),
		}
		if mc.spawnAttackTask(ctx, evt, []Credential{cred}, "credential_pivot") {
			mc.credentialPivots[key] = struct{}{}
			spawned++
		}
	}
	if spawned > 0 {
		mc.emitLog(fmt.Sprintf("MainCoordinator queued %d credential pivot task(s) from %s:%d",
			spawned, host, origin.Port))
	}
}

func (mc *MainCoordinator) collectHackTricksIntelForPort(port int) ([]string, string) {
	if mc.attackData == nil {
		return nil, ""
	}
	node := mc.attackData.FindPortNode(port)
	if node == nil {
		return nil, ""
	}

	cveSet := make(map[string]struct{})
	notes := make([]string, 0, len(node.Insights))
	for _, in := range node.Insights {
		if !strings.EqualFold(strings.TrimSpace(in.Source), "hacktricks") {
			continue
		}
		topic := strings.TrimSpace(in.Topic)
		if topic != "" {
			for _, cve := range extractCVEs(topic) {
				cveSet[cve] = struct{}{}
			}
		}
		detail := strings.TrimSpace(in.Detail)
		if detail != "" {
			for _, cve := range extractCVEs(detail) {
				cveSet[cve] = struct{}{}
			}
			notes = append(notes, detail)
		}
	}

	cves := make([]string, 0, len(cveSet))
	for cve := range cveSet {
		cves = append(cves, cve)
	}
	sort.Strings(cves)
	return cves, strings.Join(notes, " | ")
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
	sb.WriteString("Focus on endpoint and parameter driven vulnerability validation.\n")
	sb.WriteString("Do NOT run broad web reconnaissance tools (webfuzz dir/vhost, dirb, gobuster, nikto).\n")
	sb.WriteString("Use curl/sqlmap/manual payload checks on discovered endpoints/parameters only.\n")
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

	sb.WriteString("\nAttack plan (endpoint + parameter based):\n")
	planLines := buildWebAttackPlanLines(endpoints, params)
	for _, line := range planLines {
		fmt.Fprintf(&sb, "- %s\n", line)
	}
	sb.WriteString("\nFor each endpoint, run baseline request first and then targeted payloads per category.\n")
	sb.WriteString("Validate signal by status/body length/latency differences and concrete evidence strings.\n")
	sb.WriteString("Prioritize high-value checks first: auth bypass, SQLi, command injection, path traversal, IDOR.\n")
	sb.WriteString("Avoid repeated identical commands when previous attempts had no signal.\n")

	return sb.String()
}

func buildAttackPrompt(host string, evt ServiceIdentified, creds []Credential) string {
	service := evt.Service
	if service == "" {
		service = "unknown"
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "You are an AttackAgent for non-HTTP service %s:%d (%s).\n", host, evt.Port, service)
	sb.WriteString("Focus on service-specific validation and exploitation steps only for this port.\n")
	sb.WriteString("Do NOT run broad web reconnaissance tools (webfuzz dir/vhost, dirb, gobuster, nikto).\n")
	sb.WriteString("Use memory action for important findings (credentials, vulnerabilities, access level), then complete.\n\n")
	sb.WriteString("Service-specific attack logic:\n")
	for _, step := range serviceAttackSteps(service) {
		fmt.Fprintf(&sb, "- %s\n", step)
	}

	sb.WriteString("\nHackTricks-driven priorities:\n")
	sb.WriteString("- Prioritize techniques that match recon notes and attack vectors first.\n")
	sb.WriteString("- Validate known CVEs before broad brute-force activity.\n")
	sb.WriteString("- If recon notes include default credentials or misconfig hints, test those early.\n")

	sb.WriteString("\nKnown CVEs:\n")
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

	sb.WriteString("\nKnown reusable credentials:\n")
	if len(creds) == 0 {
		sb.WriteString("- (none)\n")
	} else {
		for _, cred := range creds {
			svc := strings.TrimSpace(cred.Service)
			if svc == "" {
				svc = service
			}
			fmt.Fprintf(&sb, "- %s %s:%s [%s]\n", svc, cred.Username, cred.Password, cred.Source)
		}
		sb.WriteString("- Attempt authenticated checks with these credentials before brute-force probes.\n")
	}

	sb.WriteString("\nPrioritize: known CVE validation -> authentication weaknesses -> misconfiguration abuse.\n")
	return sb.String()
}

func buildWebAttackPlanLines(endpoints []EndpointInfo, params []ParamInfo) []string {
	endpointSet := make(map[string]struct{})
	paramByPath := make(map[string][]ParamInfo)

	for _, ep := range endpoints {
		path := strings.TrimSpace(ep.Path)
		if path == "" {
			continue
		}
		endpointSet[path] = struct{}{}
	}
	for _, p := range params {
		path := strings.TrimSpace(p.Path)
		if path == "" {
			continue
		}
		endpointSet[path] = struct{}{}
		paramByPath[path] = append(paramByPath[path], p)
	}

	if len(endpointSet) == 0 {
		return []string{"No endpoint list provided; validate root and any obvious auth/API routes with targeted payloads"}
	}

	paths := make([]string, 0, len(endpointSet))
	for p := range endpointSet {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	lines := make([]string, 0, len(paths))
	for _, path := range paths {
		pList := paramByPath[path]
		paramNames := make([]string, 0, len(pList))
		for _, p := range pList {
			label := strings.TrimSpace(p.Name)
			if p.ParamType != "" {
				label += "(" + p.ParamType + ")"
			}
			if label != "" {
				paramNames = append(paramNames, label)
			}
		}
		sort.Strings(paramNames)
		checks := inferWebAttackChecks(path, pList)
		lines = append(lines, fmt.Sprintf("%s -> params=[%s], checks=[%s]",
			path,
			joinOrDash(paramNames),
			joinOrDash(checks)))
	}
	return lines
}

func inferWebAttackChecks(path string, params []ParamInfo) []string {
	uniq := make(map[string]struct{})
	add := func(v string) {
		if v != "" {
			uniq[v] = struct{}{}
		}
	}

	pathLower := strings.ToLower(path)
	switch {
	case strings.Contains(pathLower, "login"), strings.Contains(pathLower, "auth"):
		add("auth bypass")
		add("sqli")
	case strings.Contains(pathLower, "admin"):
		add("idor")
		add("authz bypass")
	case strings.Contains(pathLower, "upload"), strings.Contains(pathLower, "file"):
		add("path traversal")
		add("file handling abuse")
	case strings.Contains(pathLower, "api"):
		add("idor")
	}

	for _, p := range params {
		n := strings.ToLower(strings.TrimSpace(p.Name))
		switch {
		case strings.Contains(n, "id"), strings.Contains(n, "user"), strings.Contains(n, "account"), strings.Contains(n, "order"):
			add("idor")
			add("sqli")
		case strings.Contains(n, "q"), strings.Contains(n, "search"), strings.Contains(n, "msg"), strings.Contains(n, "comment"):
			add("xss")
		case strings.Contains(n, "cmd"), strings.Contains(n, "exec"), strings.Contains(n, "ping"), strings.Contains(n, "host"):
			add("command injection")
		case strings.Contains(n, "file"), strings.Contains(n, "path"), strings.Contains(n, "template"), strings.Contains(n, "view"):
			add("path traversal")
			add("ssti")
		case strings.Contains(n, "name"), strings.Contains(n, "email"):
			add("xss")
			add("sqli")
		}
	}

	// Baseline checks are always required.
	add("baseline diff analysis")
	if len(uniq) == 1 {
		add("sqli")
		add("xss")
	}

	out := make([]string, 0, len(uniq))
	for v := range uniq {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func joinOrDash(items []string) string {
	if len(items) == 0 {
		return "-"
	}
	return strings.Join(items, ", ")
}

func serviceAttackSteps(service string) []string {
	switch normalizeServiceName(strings.ToLower(strings.TrimSpace(service))) {
	case "ftp":
		return []string{
			"Check anonymous FTP access and writable locations.",
			"Validate FTP server version against known backdoors (e.g. vsftpd 2.3.4).",
			"Attempt credentialed login and enumerate downloadable configuration data.",
		}
	case "ssh":
		return []string{
			"Collect banner/auth methods and identify weak crypto configuration.",
			"Test discovered credentials for interactive SSH access and restricted shell bypass.",
			"If access succeeds, collect local privilege-escalation evidence.",
		}
	case "mysql", "mssql", "postgresql":
		return []string{
			"Attempt authenticated connection with discovered/default credentials.",
			"Enumerate databases/users/privileges and look for weak auth or dangerous grants.",
			"Validate high-impact execution primitives (e.g. xp_cmdshell/UDF/COPY PROGRAM) safely.",
		}
	case "smb":
		return []string{
			"Enumerate shares and access rights with/without credentials.",
			"Check SMB protocol/signing configuration and known exploitability indicators.",
			"Test credential reuse for IPC$/ADMIN$ access and remote execution primitives.",
		}
	case "redis":
		return []string{
			"Verify authentication requirement and dangerous commands availability.",
			"Check write-to-disk primitives and potential authorized_keys/crontab abuse paths.",
			"Record any configuration that enables privilege escalation or persistence.",
		}
	case "winrm", "rdp":
		return []string{
			"Validate discovered credentials against remote management service.",
			"Confirm granted privilege level and host access scope.",
			"Collect evidence for follow-on lateral movement opportunities.",
		}
	default:
		return []string{
			"Perform version and banner based vulnerability validation.",
			"Test authentication weaknesses and known default credentials.",
			"Capture concrete exploit/access evidence and stop after deterministic validation.",
		}
	}
}

func isHTTPService(service string) bool {
	switch strings.ToLower(service) {
	case "http", "https", "http-proxy", "https-alt":
		return true
	default:
		return false
	}
}
