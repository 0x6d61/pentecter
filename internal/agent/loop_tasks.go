// Package agent - loop_tasks.go は Loop の SubTask 関連ハンドラを定義する。
package agent

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/0x6d61/pentecter/pkg/schema"
)

var cvePattern = regexp.MustCompile(`(?i)\bCVE-\d{4}-\d{4,7}\b`)
var pathPattern = regexp.MustCompile(`(/[A-Za-z0-9._~!$&'()*+,;=:@%/-]+)`)
var paramPattern = regexp.MustCompile(`(?i)\b(?:param(?:eter)?|field|key)\s*[:=]?\s*([A-Za-z_][A-Za-z0-9_-]{0,63})`)
var queryParamPattern = regexp.MustCompile(`[?&]([A-Za-z_][A-Za-z0-9_-]{0,63})=`)
var userPattern = regexp.MustCompile(`(?i)\b(?:user(?:name)?|login)\s*[:=]\s*([^\s,;]+)`)
var passPattern = regexp.MustCompile(`(?i)\b(?:pass(?:word)?|pwd)\s*[:=]\s*([^\s,;]+)`)
var pairPattern = regexp.MustCompile(`\b([A-Za-z0-9_.-]{1,64}):([^\s,;]{1,128})\b`)

const (
	webReconBaseBackoffDelay   = 15 * time.Second
	webReconMaxBackoffDelay    = 5 * time.Minute
	webReconParallelRetryDelay = 2 * time.Second
	webReconStallThreshold     = 3
)

type webReconRespawnState struct {
	LastPending     int
	NoProgressCount int
	NextRetryAt     time.Time
}

// drainCompletedTasks は完了済みサブタスクの結果を取り出し、テキストとして返す。
// Brain.Think() の直前に呼ばれ、結果が lastToolOutput に注入される。
// SubAgent が MaxTurns で力尽きた場合、残タスクがあれば SubAgent を再 spawn する。
func (l *Loop) drainCompletedTasks(ctx context.Context) string {
	if l.taskMgr == nil {
		return ""
	}
	// Retry web recon ports whose backoff timers have elapsed.
	l.retryDeferredWebRecon(ctx)
	completed := l.taskMgr.DrainCompleted()
	if len(completed) == 0 {
		return ""
	}
	var sb strings.Builder
	for _, task := range completed {
		fmt.Fprintf(&sb, "=== SubTask Completed: %s ===\n", task.ID)
		sb.WriteString(l.buildTaskResult(task))
		sb.WriteString("\n")

		// Re-spawn: SubAgent が MaxTurns で力尽きた場合、残タスクがあれば再 spawn
		if task.Metadata.Phase == "web_recon" && task.Metadata.Port > 0 {
			l.handleWebReconCompletionRespawn(ctx, task.Metadata.Port)
		}

		if task.Metadata.Phase == "web_recon" && task.Metadata.Port > 0 {
			l.emitDomainEvent(ctx, AgentComplete{
				DomainEventBase: NewDomainEventBase(l.target.ID, l.target.Host, AgentKindWebRecon),
				AgentID:         task.ID,
				AgentType:       string(AgentKindWebRecon),
				Summary:         task.Summary(),
			})
			if task.Status == TaskStatusCompleted && l.attackData != nil && !l.attackData.PortHasPending(task.Metadata.Port) {
				endpoints, params, vhosts := l.attackData.SnapshotWebSurface(task.Metadata.Port)
				l.emitDomainEvent(ctx, WebReconComplete{
					DomainEventBase: NewDomainEventBase(l.target.ID, l.target.Host, AgentKindWebRecon),
					Port:            task.Metadata.Port,
					Endpoints:       endpoints,
					Params:          params,
					Vhosts:          vhosts,
				})
			}
		}
		if task.Metadata.Phase == "web_attack" && task.Metadata.Port > 0 {
			l.emitAttackDomainEvents(ctx, task, AgentKindWebAttack)
			l.emitDomainEvent(ctx, AgentComplete{
				DomainEventBase: NewDomainEventBase(l.target.ID, l.target.Host, AgentKindWebAttack),
				AgentID:         task.ID,
				AgentType:       string(AgentKindWebAttack),
				Summary:         task.Summary(),
			})
		}
		if task.Metadata.Phase == "attack" && task.Metadata.Port > 0 {
			l.emitAttackDomainEvents(ctx, task, AgentKindAttack)
			l.emitDomainEvent(ctx, AgentComplete{
				DomainEventBase: NewDomainEventBase(l.target.ID, l.target.Host, AgentKindAttack),
				AgentID:         task.ID,
				AgentType:       string(AgentKindAttack),
				Summary:         task.Summary(),
			})
		}

		// ReconAgent 完了時: ServiceIdentified emit + 非 HTTP ポートのチェックリスト生成
		if task.Metadata.Phase == "recon" && l.attackData != nil && task.Status == TaskStatusCompleted {
			identifiedCount := l.emitServiceIdentifiedFromRecon(ctx, task)
			hasKnowledge := l.knowledgeStore != nil
			for _, port := range l.attackData.NonHTTPPortsWithoutChecklist() {
				cl := GenerateChecklist(port.Service, port.Banner, hasKnowledge)
				l.attackData.SetChecklist(port.Port, cl)
			}
			l.emit(Event{Type: EventLog, Source: SourceSystem,
				Message: fmt.Sprintf("ReconAgent %s completed — service_identified=%d, checklists generated for non-HTTP ports", task.ID, identifiedCount)})
		}
	}
	return sb.String()
}

func (l *Loop) ensureWebReconRespawnState(port int) *webReconRespawnState {
	if l.webReconRespawn == nil {
		l.webReconRespawn = make(map[int]*webReconRespawnState)
	}
	state, ok := l.webReconRespawn[port]
	if !ok {
		state = &webReconRespawnState{}
		l.webReconRespawn[port] = state
	}
	return state
}

func (l *Loop) clearWebReconRespawnState(port int) {
	if l.webReconRespawn == nil {
		return
	}
	delete(l.webReconRespawn, port)
}

func webReconBackoffDelay(noProgressCount int) time.Duration {
	if noProgressCount <= 0 {
		noProgressCount = 1
	}
	delay := webReconBaseBackoffDelay
	for i := 1; i < noProgressCount; i++ {
		delay *= 2
		if delay >= webReconMaxBackoffDelay {
			return webReconMaxBackoffDelay
		}
	}
	if delay > webReconMaxBackoffDelay {
		return webReconMaxBackoffDelay
	}
	return delay
}

func (l *Loop) trySpawnWebReconPort(ctx context.Context, port int) {
	if l == nil || l.attackData == nil || l.reconRunner == nil {
		return
	}
	if !l.attackData.PortHasPending(port) {
		l.clearWebReconRespawnState(port)
		return
	}
	portNode := l.attackData.FindPortNode(port)
	if portNode == nil {
		l.clearWebReconRespawnState(port)
		return
	}
	state := l.ensureWebReconRespawnState(port)
	switch l.reconRunner.TrySpawnWebReconForPort(ctx, portNode) {
	case ReconSpawnStarted:
		state.NextRetryAt = time.Time{}
	case ReconSpawnDeferredMaxParallel:
		state.NextRetryAt = time.Now().Add(webReconParallelRetryDelay)
	case ReconSpawnNoPending:
		l.clearWebReconRespawnState(port)
	case ReconSpawnFailed:
		delay := webReconBackoffDelay(max(1, state.NoProgressCount))
		state.NextRetryAt = time.Now().Add(delay)
	}
}

func (l *Loop) retryDeferredWebRecon(ctx context.Context) {
	if l == nil || l.reconRunner == nil || l.attackData == nil || len(l.webReconRespawn) == 0 {
		return
	}
	now := time.Now()
	for port, state := range l.webReconRespawn {
		if state == nil {
			delete(l.webReconRespawn, port)
			continue
		}
		if state.NextRetryAt.IsZero() || now.Before(state.NextRetryAt) {
			continue
		}
		l.trySpawnWebReconPort(ctx, port)
	}
}

func (l *Loop) handleWebReconCompletionRespawn(ctx context.Context, port int) {
	if l == nil || l.reconRunner == nil || l.attackData == nil || port <= 0 {
		return
	}
	pending := l.attackData.CountPendingForPort(port)
	if pending <= 0 {
		l.clearWebReconRespawnState(port)
		return
	}

	state := l.ensureWebReconRespawnState(port)
	if state.LastPending > 0 && pending >= state.LastPending {
		state.NoProgressCount++
		delay := webReconBackoffDelay(state.NoProgressCount)
		state.NextRetryAt = time.Now().Add(delay)
		state.LastPending = pending
		l.emit(Event{
			Type:   EventLog,
			Source: SourceSystem,
			Message: fmt.Sprintf(
				"[RECON] No progress on port %d (pending=%d, no_progress=%d). Backoff retry in %s.",
				port, pending, state.NoProgressCount, delay,
			),
		})
		if state.NoProgressCount >= webReconStallThreshold {
			l.emit(Event{
				Type: EventStalled,
				Message: fmt.Sprintf(
					"Web recon on port %d appears stalled (no progress %d times). Will keep retrying with backoff.",
					port, state.NoProgressCount,
				),
			})
		}
		return
	}

	// First completion or progress observed: retry immediately.
	state.LastPending = pending
	state.NoProgressCount = 0
	state.NextRetryAt = time.Time{}
	l.trySpawnWebReconPort(ctx, port)
}

func (l *Loop) emitServiceIdentifiedFromRecon(ctx context.Context, task *SubTask) int {
	if l == nil || l.attackData == nil {
		return 0
	}
	ports := l.attackData.SnapshotPorts()
	if len(ports) == 0 {
		return 0
	}

	evidence := task.FullOutput()
	if len(task.Findings) > 0 {
		if evidence != "" {
			evidence += "\n"
		}
		evidence += strings.Join(task.Findings, "\n")
	}

	count := 0
	allowGlobalFallback := len(ports) == 1
	for _, port := range ports {
		scope := selectReconEvidenceForPort(evidence, port, allowGlobalFallback)
		cves := extractCVEs(scope)
		vectors := inferAttackVectors(scope, cves)
		notes := buildServiceNotes(cves, vectors)
		if l.attackData != nil {
			topic := port.Service
			if len(cves) > 0 {
				topic = cves[0]
			}
			l.attackData.AddInsight(l.target.Host, port.Port, Insight{
				Source: "hacktricks",
				Topic:  topic,
				Detail: notes,
			})
		}

		l.emitDomainEvent(ctx, ServiceIdentified{
			DomainEventBase: NewDomainEventBase(l.target.ID, l.target.Host, AgentKindRecon),
			Port:            port.Port,
			Service:         port.Service,
			CVEs:            cves,
			AttackVectors:   vectors,
			Notes:           notes,
		})
		count++
	}
	return count
}

func selectReconEvidenceForPort(allEvidence string, port PortSnapshot, allowGlobalFallback bool) string {
	if allEvidence == "" {
		return ""
	}

	service := strings.ToLower(strings.TrimSpace(port.Service))
	banner := strings.ToLower(strings.TrimSpace(port.Banner))
	portHints := []string{
		fmt.Sprintf("port %d", port.Port),
		fmt.Sprintf("%d/", port.Port),
		fmt.Sprintf(":%d", port.Port),
	}

	matched := make([]string, 0, 16)
	for _, line := range strings.Split(allEvidence, "\n") {
		lineLower := strings.ToLower(line)
		if service != "" && strings.Contains(lineLower, service) {
			matched = append(matched, line)
			continue
		}
		if banner != "" && strings.Contains(lineLower, banner) {
			matched = append(matched, line)
			continue
		}
		for _, hint := range portHints {
			if strings.Contains(lineLower, hint) {
				matched = append(matched, line)
				break
			}
		}
	}

	// Fallback: 単一サービス時のみ全体証拠を使う。
	if len(matched) == 0 && allowGlobalFallback {
		return allEvidence
	}
	return strings.Join(matched, "\n")
}

func extractCVEs(text string) []string {
	if text == "" {
		return nil
	}
	matches := cvePattern.FindAllString(text, -1)
	if len(matches) == 0 {
		return nil
	}
	uniq := make(map[string]struct{}, len(matches))
	for _, m := range matches {
		uniq[strings.ToUpper(m)] = struct{}{}
	}
	out := make([]string, 0, len(uniq))
	for cve := range uniq {
		out = append(out, cve)
	}
	sort.Strings(out)
	return out
}

func inferAttackVectors(text string, cves []string) []string {
	textLower := strings.ToLower(text)
	uniq := map[string]struct{}{}
	add := func(v string) {
		if v != "" {
			uniq[v] = struct{}{}
		}
	}

	keywordVectors := []struct {
		keyword string
		vector  string
	}{
		{"default credential", "default credentials"},
		{"anonymous login", "anonymous login"},
		{"brute force", "credential brute force"},
		{"backdoor", "backdoor validation"},
		{"misconfiguration", "misconfiguration checks"},
		{"remote code execution", "remote code execution"},
		{"command injection", "command injection"},
		{"privilege escalation", "privilege escalation"},
		{"weak password", "weak password checks"},
	}
	for _, kv := range keywordVectors {
		if strings.Contains(textLower, kv.keyword) {
			add(kv.vector)
		}
	}
	if len(cves) > 0 {
		add("cve validation")
	}

	if len(uniq) == 0 {
		return nil
	}
	out := make([]string, 0, len(uniq))
	for v := range uniq {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func buildServiceNotes(cves, vectors []string) string {
	parts := make([]string, 0, 2)
	if len(cves) > 0 {
		parts = append(parts, "Identified CVEs: "+strings.Join(cves, ", "))
	}
	if len(vectors) > 0 {
		parts = append(parts, "Potential vectors: "+strings.Join(vectors, ", "))
	}
	if len(parts) == 0 {
		return "Recon research completed"
	}
	return strings.Join(parts, " | ")
}

func (l *Loop) emitAttackDomainEvents(ctx context.Context, task *SubTask, kind AgentKind) {
	if l == nil || task == nil || task.Status != TaskStatusCompleted || task.Metadata.Port <= 0 {
		return
	}

	host := l.target.Host
	port := task.Metadata.Port
	service := normalizeTaskServiceName(task.Metadata.Service)
	if service == "" && l.attackData != nil {
		if node := l.attackData.FindPortNode(port); node != nil {
			service = normalizeTaskServiceName(node.Service)
		}
	}
	if service == "" {
		service = "unknown"
	}
	source := string(kind)
	domainBusEnabled := l.domainEvents != nil

	seenVuln := make(map[string]struct{})
	seenCred := make(map[string]struct{})
	emitted := 0
	exploitEmitted := false
	accessEmitted := false

	emitExploit := func(vulnType, detail string) {
		if exploitEmitted {
			return
		}
		vt := vulnType
		if vt == "" {
			vt = detectVulnType(detail)
		}
		if vt == "" {
			vt = "generic"
		}
		impact := inferExploitImpact(detail)
		l.emitDomainEvent(ctx, ExploitSuccess{
			DomainEventBase: NewDomainEventBase(l.target.ID, host, kind),
			Port:            port,
			VulnType:        vt,
			Impact:          impact,
			Detail:          strings.TrimSpace(detail),
		})
		if l.attackData != nil && !domainBusEnabled {
			l.attackData.AddInsight(host, port, Insight{
				Source: source,
				Topic:  "exploit:" + vt,
				Detail: strings.TrimSpace(detail),
			})
		}
		exploitEmitted = true
		emitted++
	}

	emitAccess := func(level, detail string) {
		if accessEmitted {
			return
		}
		lvl := level
		if lvl == "" {
			lvl = "user"
		}
		l.emitDomainEvent(ctx, AccessGained{
			DomainEventBase: NewDomainEventBase(l.target.ID, host, kind),
			Port:            port,
			Service:         service,
			Level:           lvl,
		})
		if l.attackData != nil && !domainBusEnabled {
			l.attackData.AddInsight(host, port, Insight{
				Source: source,
				Topic:  "access_gained",
				Detail: strings.TrimSpace(detail),
			})
		}
		accessEmitted = true
		emitted++
	}

	for _, mem := range task.Memories {
		if mem == nil {
			continue
		}
		text := strings.TrimSpace(mem.Title + " " + mem.Description)
		switch mem.Type {
		case schema.MemoryVulnerability:
			vulnType := detectVulnType(text)
			if vulnType == "" {
				vulnType = "generic"
			}
			path := extractPathFromText(text)
			param := extractParamFromText(text)
			severity := detectSeverity(mem.Severity, text)
			evidence := strings.TrimSpace(mem.Description)
			if evidence == "" {
				evidence = strings.TrimSpace(mem.Title)
			}
			if evidence == "" {
				evidence = "vulnerability recorded by sub-agent"
			}
			key := fmt.Sprintf("%d|%s|%s|%s|%s", port, vulnType, path, param, evidence)
			if _, exists := seenVuln[key]; !exists {
				seenVuln[key] = struct{}{}
				l.emitDomainEvent(ctx, VulnFound{
					DomainEventBase: NewDomainEventBase(l.target.ID, host, kind),
					Port:            port,
					Path:            path,
					Param:           param,
					VulnType:        vulnType,
					Evidence:        evidence,
					Severity:        severity,
				})
				if l.attackData != nil && !domainBusEnabled {
					treePath := path
					if treePath == "" {
						if isHTTPService(service) {
							treePath = "/"
						} else {
							treePath = ""
						}
					}
					if treePath != "" && isHTTPService(service) && l.attackData.findNode(host, port, treePath) == nil {
						// Attack stage may discover a path not present in recon tree yet.
						// Fall back to port root to avoid dropping findings.
						treePath = "/"
					}
					l.attackData.AddFinding(host, port, treePath, Finding{
						Param:    param,
						Category: vulnType,
						Evidence: evidence,
						Severity: severity,
					})
					l.attackData.AddInsight(host, port, Insight{
						Source: source,
						Topic:  "vuln:" + vulnType,
						Detail: evidence,
					})
				}
				emitted++
			}
			if hasExploitSignal(text) {
				emitExploit(vulnType, text)
			}

		case schema.MemoryCredential:
			user, pass := extractCredentialPair(text)
			if user == "" && pass == "" {
				continue
			}
			if user == "" {
				user = "unknown"
			}
			if pass == "" {
				pass = "unknown"
			}
			credService := inferServiceFromText(text, service)
			credKey := fmt.Sprintf("%s|%s|%s|%d", credService, user, pass, port)
			if _, exists := seenCred[credKey]; exists {
				continue
			}
			seenCred[credKey] = struct{}{}
			l.emitDomainEvent(ctx, CredentialFound{
				DomainEventBase: NewDomainEventBase(l.target.ID, host, kind),
				Port:            port,
				Service:         credService,
				Username:        user,
				Password:        pass,
			})
			if l.attackData != nil && !domainBusEnabled {
				l.attackData.AddCredential(host, port, Credential{
					Service:  credService,
					Username: user,
					Password: pass,
					Source:   source,
				})
				l.attackData.AddInsight(host, port, Insight{
					Source: source,
					Topic:  "credential_found",
					Detail: fmt.Sprintf("%s %s:%s", credService, user, pass),
				})
			}
			emitted++

		case schema.MemoryArtifact, schema.MemoryNote:
			if hasExploitSignal(text) {
				emitExploit(detectVulnType(text), text)
			}
		}

		if !accessEmitted {
			if level, ok := inferAccessLevel(text); ok {
				emitAccess(level, text)
			}
		}
	}

	output := task.FullOutput()
	if !exploitEmitted && hasExploitSignal(output) {
		emitExploit("", output)
	}
	if !accessEmitted {
		if level, ok := inferAccessLevel(output); ok {
			emitAccess(level, output)
		}
	}

	if emitted > 0 {
		l.emit(Event{
			Type:    EventLog,
			Source:  SourceSystem,
			Message: fmt.Sprintf("%s %s emitted %d domain security events", kind, task.ID, emitted),
		})
	}
}

func normalizeTaskServiceName(service string) string {
	return strings.ToLower(strings.TrimSpace(service))
}

func detectVulnType(text string) string {
	switch {
	case containsCI(text, "sql injection"), containsCI(text, "sqli"):
		return "sqli"
	case containsCI(text, "xss"), containsCI(text, "cross-site scripting"):
		return "xss"
	case containsCI(text, "ssti"), containsCI(text, "template injection"):
		return "ssti"
	case containsCI(text, "command injection"):
		return "command_injection"
	case containsCI(text, "path traversal"), containsCI(text, "directory traversal"), containsCI(text, "lfi"):
		return "path_traversal"
	case containsCI(text, "idor"):
		return "idor"
	case containsCI(text, "rce"), containsCI(text, "remote code execution"):
		return "rce"
	case containsCI(text, "backdoor"):
		return "backdoor"
	default:
		return ""
	}
}

func detectSeverity(preferred, text string) string {
	s := strings.ToLower(strings.TrimSpace(preferred))
	switch s {
	case "critical", "high", "medium", "low", "info":
		return s
	}
	switch {
	case containsCI(text, "critical"):
		return "critical"
	case containsCI(text, "high"):
		return "high"
	case containsCI(text, "medium"):
		return "medium"
	case containsCI(text, "low"):
		return "low"
	default:
		return "info"
	}
}

func extractPathFromText(text string) string {
	if m := pathPattern.FindStringSubmatch(text); len(m) > 1 {
		return m[1]
	}
	return ""
}

func extractParamFromText(text string) string {
	if m := paramPattern.FindStringSubmatch(text); len(m) > 1 {
		return sanitizeToken(m[1])
	}
	if m := queryParamPattern.FindStringSubmatch(text); len(m) > 1 {
		return sanitizeToken(m[1])
	}
	return ""
}

func extractCredentialPair(text string) (string, string) {
	var user string
	var pass string

	if m := userPattern.FindStringSubmatch(text); len(m) > 1 {
		user = sanitizeToken(m[1])
	}
	if m := passPattern.FindStringSubmatch(text); len(m) > 1 {
		pass = sanitizeToken(m[1])
	}
	if (user == "" || pass == "") && pairPattern.MatchString(text) {
		m := pairPattern.FindStringSubmatch(text)
		if len(m) > 2 {
			if user == "" {
				user = sanitizeToken(m[1])
			}
			if pass == "" {
				pass = sanitizeToken(m[2])
			}
		}
	}
	return user, pass
}

func sanitizeToken(s string) string {
	return strings.Trim(s, " \t\r\n\"'`[](){}")
}

func inferServiceFromText(text, fallback string) string {
	for _, svc := range []string{
		"ftp", "ssh", "mysql", "mssql", "postgresql", "redis", "smb", "winrm", "rdp", "http", "https",
	} {
		if containsCI(text, svc) {
			return svc
		}
	}
	if fallback != "" {
		return fallback
	}
	return "unknown"
}

func hasExploitSignal(text string) bool {
	return containsCI(text, "exploit success") ||
		containsCI(text, "successfully exploited") ||
		containsCI(text, "auth bypass") ||
		containsCI(text, "bypass successful") ||
		containsCI(text, "shell obtained") ||
		containsCI(text, "got shell") ||
		containsCI(text, "rce achieved") ||
		containsCI(text, "code execution achieved") ||
		containsCI(text, "pwned")
}

func inferExploitImpact(text string) string {
	switch {
	case containsCI(text, "auth bypass"):
		return "authentication bypass"
	case containsCI(text, "code execution"), containsCI(text, "rce"), containsCI(text, "command injection"):
		return "remote code execution"
	case containsCI(text, "shell"):
		return "shell access"
	default:
		return "exploit validation succeeded"
	}
}

func inferAccessLevel(text string) (string, bool) {
	switch {
	case containsCI(text, "root"), containsCI(text, "system"):
		return "root", true
	case containsCI(text, "admin"):
		return "admin", true
	case containsCI(text, "user shell"), containsCI(text, "access gained"), containsCI(text, "shell obtained"):
		return "user", true
	default:
		return "", false
	}
}

// handleSpawnTask は spawn_task アクションを処理する。
func (l *Loop) handleSpawnTask(ctx context.Context, action *schema.Action) {
	if l.taskMgr == nil {
		l.emit(Event{Type: EventLog, Source: SourceSystem,
			Message: "TaskManager not configured — cannot spawn tasks"})
		l.lastToolOutput = "Error: TaskManager not configured"
		return
	}

	req := SpawnTaskRequest{
		Kind:           TaskKindSmart,
		Goal:           action.TaskGoal,
		Command:        action.Command,
		TargetHost:     l.target.Host,
		TargetID:       l.target.ID,
		MaxTurns:       action.TaskMaxTurns,
		AttackDataTree: l.attackData,
		Metadata: TaskMetadata{
			Port:    action.TaskPort,
			Service: action.TaskService,
			Phase:   action.TaskPhase,
		},
	}

	taskID, err := l.taskMgr.SpawnTask(ctx, req)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to spawn task: %v", err)
		l.emit(Event{Type: EventLog, Source: SourceSystem, Message: errMsg})
		l.lastToolOutput = "Error: " + err.Error()
		return
	}

	// Block-based rendering event
	l.emit(Event{
		Type:    EventSubTaskStart,
		TaskID:  taskID,
		Message: req.Goal,
	})

	msg := fmt.Sprintf("Task spawned: %s (goal=%s)", taskID, req.Goal)
	l.emit(Event{Type: EventLog, Source: SourceSystem, Message: msg})
	l.lastToolOutput = msg
}

// handleWait は wait アクションを処理する。指定タスクの完了を待つ。
func (l *Loop) handleWait(ctx context.Context, action *schema.Action) {
	if l.taskMgr == nil {
		l.lastToolOutput = "Error: TaskManager not configured"
		return
	}

	var doneID string
	if action.TaskID != "" {
		ok := l.taskMgr.WaitTask(ctx, action.TaskID)
		if !ok {
			l.lastToolOutput = fmt.Sprintf("Error: wait for task %s cancelled or not found", action.TaskID)
			return
		}
		doneID = action.TaskID
	} else {
		doneID = l.taskMgr.WaitAny(ctx)
		if doneID == "" {
			l.lastToolOutput = "Error: wait cancelled (context done)"
			return
		}
	}

	task, ok := l.taskMgr.GetTask(doneID)
	if !ok {
		l.lastToolOutput = fmt.Sprintf("Error: task %s not found after wait", doneID)
		return
	}

	l.lastToolOutput = l.buildTaskResult(task)

	// Post-wait drain: 待機中に届いたユーザーメッセージを回収
	if msg := l.drainUserMsg(); msg != "" {
		l.pendingUserMsg = msg
	}
}

// handleKillTask は kill_task アクションを処理する。
func (l *Loop) handleKillTask(action *schema.Action) {
	if l.taskMgr == nil {
		l.lastToolOutput = "Error: TaskManager not configured"
		return
	}

	err := l.taskMgr.KillTask(action.TaskID)
	if err != nil {
		l.lastToolOutput = fmt.Sprintf("Error: %v", err)
		return
	}

	l.lastToolOutput = fmt.Sprintf("Task %s cancelled", action.TaskID)
	l.emit(Event{Type: EventLog, Source: SourceSystem,
		Message: fmt.Sprintf("Task %s cancelled", action.TaskID)})
}

// buildTaskResult はサブタスクの完了結果テキストを組み立てる。
func (l *Loop) buildTaskResult(task *SubTask) string {
	var sb strings.Builder
	sb.WriteString(task.Summary())
	sb.WriteString("\n")

	// Findings を追加
	if len(task.Findings) > 0 {
		sb.WriteString("--- findings ---\n")
		for _, f := range task.Findings {
			sb.WriteString("- ")
			sb.WriteString(f)
			sb.WriteString("\n")
		}
	}

	// 出力（2000文字に制限）
	output := task.FullOutput()
	if output != "" {
		sb.WriteString("--- output ---\n")
		if len(output) > 2000 {
			sb.WriteString(output[:2000])
			sb.WriteString("\n... (truncated)\n")
		} else {
			sb.WriteString(output)
			sb.WriteString("\n")
		}
	}

	// Entity をターゲットに追加
	if len(task.Entities) > 0 {
		l.target.AddEntities(task.Entities)
	}

	// AttackDataTree 連携: web_recon SubTask 完了時にポートの全タスクを Complete にする
	if l.attackData != nil && task.Metadata.Phase == "web_recon" && task.Metadata.Port > 0 {
		l.attackData.CompleteAllPortTasks(task.Metadata.Port)

		// Target に最新の AttackDataTree を反映
		l.target.SetAttackData(l.attackData)
	}

	return sb.String()
}
