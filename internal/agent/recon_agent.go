// Package agent -- recon_agent.go は ReconAgent の spawn ロジックを定義する。
// ReconAgent は nmap スキャン + HackTricks 知識ベース調査を自律的に行い、
// HTTP ポート発見時に WebReconAgent を自動 spawn する。
package agent

import (
	"context"
	"fmt"

	"github.com/0x6d61/pentecter/internal/knowledge"
)

// SpawnReconAgentConfig は ReconAgent の spawn パラメーター。
type SpawnReconAgentConfig struct {
	TaskMgr        *TaskManager
	KnowledgeStore *knowledge.Store
	AttackData     *AttackDataTree
	ReconRunner    *ReconRunner
	DomainEvents   chan<- DomainEvent
	TargetHost     string
	TargetID       int
	MemDir         string
}

// SpawnReconAgent は ReconAgent を TaskManager 経由で spawn する。
// ReconBrain が nil（CanSpawnRecon() == false）の場合はエラーを返す。
func SpawnReconAgent(ctx context.Context, cfg SpawnReconAgentConfig) (string, error) {
	if cfg.TaskMgr == nil {
		return "", fmt.Errorf("recon_agent: TaskManager is nil")
	}
	if !cfg.TaskMgr.CanSpawnRecon() {
		return "", fmt.Errorf("recon_agent: ReconBrain is not configured")
	}

	prompt := buildReconPrompt(cfg.TargetHost)

	// reconSpawnCb: HTTP ポート検出時にドメインイベントを emit（または直接 WebRecon spawn）
	var reconSpawnCb func(context.Context)
	if cfg.AttackData != nil {
		reconSpawnCb = func(spawnCtx context.Context) {
			for _, port := range cfg.AttackData.PendingHTTPPorts() {
				if cfg.DomainEvents != nil {
					evt := PortDiscovered{
						DomainEventBase: NewDomainEventBase(cfg.TargetID, cfg.TargetHost, AgentKindRecon),
						Port:            port.Port,
						Service:         port.Service,
						Banner:          port.Banner,
					}
					select {
					case cfg.DomainEvents <- evt:
					case <-spawnCtx.Done():
						return
					}
					continue
				}
				if cfg.ReconRunner != nil {
					cfg.ReconRunner.SpawnWebReconForPort(spawnCtx, port)
				}
			}
		}
	}

	taskID, err := cfg.TaskMgr.SpawnTask(ctx, SpawnTaskRequest{
		Kind:           TaskKindSmart,
		Goal:           fmt.Sprintf("Reconnaissance on %s", cfg.TargetHost),
		Command:        prompt,
		TargetHost:     cfg.TargetHost,
		TargetID:       cfg.TargetID,
		MaxTurns:       30,
		AttackDataTree: cfg.AttackData,
		MemDir:         cfg.MemDir,
		KnowledgeStore: cfg.KnowledgeStore,
		ReconSpawnCb:   reconSpawnCb,
		AgentKind:      AgentKindRecon,
		IsReconAgent:   true,
		Metadata: TaskMetadata{
			Phase: "recon",
		},
	})
	if err != nil {
		return "", fmt.Errorf("recon_agent: spawn failed: %w", err)
	}

	return taskID, nil
}

// buildReconPrompt は ReconAgent 用の詳細なワークフロープロンプトを生成する。
func buildReconPrompt(host string) string {
	return fmt.Sprintf(`You are performing initial reconnaissance on target: %s

WORKFLOW -- Execute these steps in order:

1. FULL PORT SCAN:
   nmap -sV -sC -p- %s
   This comprehensive scan discovers ALL open ports and identifies services.
   Record results with "memory" action.

2. KNOWLEDGE RESEARCH (for EACH discovered service):
   For each service found by nmap:
   a. Use "search_knowledge" to find attack techniques:
      - Search: "<service_name> <version> exploit"
      - Search: "<service_name> pentesting"
      - Example: "vsftpd 2.3.4 exploit", "apache 2.4.49 pentesting"
   b. Use "read_knowledge" to read the most relevant articles
   c. Record key attack vectors with "memory" action:
      - Known CVEs and exploits
      - Default credentials
      - Common misconfigurations
      - Recommended tools and commands

3. SEARCHSPLOIT (for EACH service with a version):
   run: searchsploit "<service> <version>"
   Record any matching exploits with "memory" action.

4. FINAL SUMMARY:
   Use "memory" action (type: note) to create a prioritized attack plan:
   - List all discovered services with versions
   - For each service, note: CVEs, default creds, misconfigurations, tools
   - Prioritize: databases > auth services > file sharing > remote access > web

RULES:
- Do NOT run web enumeration tools (webfuzz, dirb, gobuster, nikto) -- HTTPAgent handles web recon
- Do NOT attempt exploitation -- leave that to the main agent
- Focus on DISCOVERY and RESEARCH only
- Record ALL findings with "memory" action before completing
- Use "complete" when all services have been researched
`, host, host)
}
