// Package agent - loop_tasks.go は Loop の SubTask 関連ハンドラを定義する。
package agent

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/0x6d61/pentecter/pkg/schema"
)

var cvePattern = regexp.MustCompile(`(?i)\bCVE-\d{4}-\d{4,7}\b`)

// drainCompletedTasks は完了済みサブタスクの結果を取り出し、テキストとして返す。
// Brain.Think() の直前に呼ばれ、結果が lastToolOutput に注入される。
// SubAgent が MaxTurns で力尽きた場合、残タスクがあれば SubAgent を再 spawn する。
func (l *Loop) drainCompletedTasks(ctx context.Context) string {
	if l.taskMgr == nil {
		return ""
	}
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
		if l.reconRunner != nil && l.attackData != nil &&
			task.Metadata.Phase == "web_recon" && task.Metadata.Port > 0 {
			if l.attackData.PortHasPendingChildren(task.Metadata.Port) {
				if portNode := l.attackData.FindPortNode(task.Metadata.Port); portNode != nil {
					if portNode.SpawnCount >= MaxRespawns {
						// リスポーン上限到達 — 残タスクをスキップ
						l.attackData.SkipAllPendingChildren(task.Metadata.Port)
						l.emit(Event{
							Type:     EventLog,
							Source:   SourceSystem,
							Message:  fmt.Sprintf("[RECON] Max re-spawns reached for port %d — skipping remaining tasks", task.Metadata.Port),
							TargetID: l.target.ID,
						})
					} else {
						l.reconRunner.SpawnWebReconForPort(ctx, portNode)
					}
				}
			}
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
			l.emitDomainEvent(ctx, AgentComplete{
				DomainEventBase: NewDomainEventBase(l.target.ID, l.target.Host, AgentKindWebAttack),
				AgentID:         task.ID,
				AgentType:       string(AgentKindWebAttack),
				Summary:         task.Summary(),
			})
		}
		if task.Metadata.Phase == "attack" && task.Metadata.Port > 0 {
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
