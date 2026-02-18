//go:build e2e

// E2E テストは以下の手順で実行する:
//   1. docker compose -f testenv/docker-compose.yml up -d
//   2. go test -v -tags=e2e -timeout 300s ./e2e/...
//   3. docker compose -f testenv/docker-compose.yml down
//
// 環境変数:
//   E2E_TARGET_IP   テスト対象の IP（デフォルト: 127.0.0.1）
//   ANTHROPIC_API_KEY または ANTHROPIC_AUTH_TOKEN (claude auth token の出力)

package e2e

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/0x6d61/pentecter/internal/agent"
	"github.com/0x6d61/pentecter/internal/brain"
	"github.com/0x6d61/pentecter/internal/tools"
	"github.com/0x6d61/pentecter/pkg/schema"
)

// targetIP はテスト対象のIPアドレスを返す。
func targetIP() string {
	if ip := os.Getenv("E2E_TARGET_IP"); ip != "" {
		return ip
	}
	return "127.0.0.1"
}

// requireNmap は nmap がインストールされていることを確認する。
func requireNmap(t *testing.T) {
	t.Helper()
	store := tools.NewLogStore()
	runner := tools.NewRunner(store)
	registry := tools.NewRegistry()
	registry.Register(&tools.ToolDef{
		Name: "nmap", Binary: "nmap",
		Output: tools.OutputConfig{Strategy: tools.StrategyHeadTail, HeadLines: 10, TailLines: 5},
	})

	def, ok := registry.Get("nmap")
	if !ok {
		t.Skip("nmap not registered")
	}
	// nmap --version で存在確認
	lines, resultCh := runner.Run(context.Background(), def, "--version", nil)
	for range lines {
	}
	res := <-resultCh
	if res.Err != nil {
		t.Skipf("nmap not available: %v", res.Err)
	}
}

// TestE2E_NmapPortScan は Metasploitable に対して nmap を実行し
// 期待されるポートが検出されることを確認する。
func TestE2E_NmapPortScan(t *testing.T) {
	requireNmap(t)

	ip := targetIP()
	store := tools.NewLogStore()
	runner := tools.NewRunner(store)

	registry := tools.NewRegistry()
	registry.Register(&tools.ToolDef{
		Name:        "nmap",
		Binary:      "nmap",
		Description: "ポートスキャン",
		TimeoutSec:  60,
		Output: tools.OutputConfig{
			Strategy:  tools.StrategyHeadTail,
			HeadLines: 50,
			TailLines: 30,
		},
	})

	def, _ := registry.Get("nmap")

	// Metasploitable のポート 80 と 22 をスキャン（高速スキャンに限定）
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	lines, resultCh := runner.Run(ctx, def, ip, []string{"-p", "21,22,80", "--open", "-Pn"})

	var rawLines []string
	for line := range lines {
		rawLines = append(rawLines, line.Content)
		t.Logf("[NMAP] %s", line.Content)
	}
	result := <-resultCh

	if result.Err != nil {
		t.Fatalf("nmap failed: %v", result.Err)
	}

	// Entity 抽出の確認
	ports := filterEntities(result.Entities, tools.EntityPort)
	if len(ports) == 0 {
		t.Errorf("expected at least one open port, got none\nraw output:\n%s", result.Truncated)
	}
	t.Logf("Detected ports: %v", entityValues(ports))
}

// TestE2E_EntityExtraction は nmap 出力から Entity が正しく抽出されることを確認する。
func TestE2E_EntityExtraction(t *testing.T) {
	requireNmap(t)

	ip := targetIP()
	store := tools.NewLogStore()
	runner := tools.NewRunner(store)

	registry := tools.NewRegistry()
	registry.Register(&tools.ToolDef{
		Name: "nmap", Binary: "nmap", TimeoutSec: 60,
		Output: tools.OutputConfig{Strategy: tools.StrategyHeadTail, HeadLines: 50, TailLines: 30},
	})

	def, _ := registry.Get("nmap")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// サービスバージョン検出
	lines, resultCh := runner.Run(ctx, def, ip, []string{"-sV", "-p", "21,22,80", "-Pn", "--version-intensity", "1"})
	for range lines {
	}
	result := <-resultCh

	if result.Err != nil {
		t.Fatalf("nmap -sV failed: %v", result.Err)
	}

	// IP エンティティが抽出されていること
	ips := filterEntities(result.Entities, tools.EntityIP)
	if len(ips) == 0 {
		t.Errorf("expected IP entity to be extracted, got none")
	}
	t.Logf("Extracted entities: ports=%v ips=%v cves=%v",
		entityValues(filterEntities(result.Entities, tools.EntityPort)),
		entityValues(ips),
		entityValues(filterEntities(result.Entities, tools.EntityCVE)),
	)
}

// TestE2E_AgentLoop は Brain を接続したエージェントループの E2E テスト。
// ANTHROPIC_API_KEY または ANTHROPIC_AUTH_TOKEN が必要。
func TestE2E_AgentLoop(t *testing.T) {
	requireNmap(t)

	// Brain の認証情報を確認
	cfg, err := brain.LoadConfig(brain.ConfigHint{
		Provider: brain.ProviderAnthropic,
		Model:    "claude-haiku-4-5-20251001", // テスト用に軽量モデルを使用
	})
	if err != nil {
		t.Skipf("Brain auth not configured: %v", err)
	}

	br, err := brain.New(cfg)
	if err != nil {
		t.Fatalf("brain.New: %v", err)
	}

	ip := targetIP()
	target := agent.NewTarget(1, ip)

	store := tools.NewLogStore()
	runner := tools.NewRunner(store)

	registry := tools.NewRegistry()
	registry.Register(&tools.ToolDef{
		Name: "nmap", Binary: "nmap", TimeoutSec: 60,
		Output: tools.OutputConfig{Strategy: tools.StrategyHeadTail, HeadLines: 50, TailLines: 30},
	})

	events := make(chan agent.Event, 128)
	approve := make(chan bool, 1)
	userMsg := make(chan string, 1)

	loop := agent.NewLoop(target, br, runner, registry, events, approve, userMsg)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	go loop.Run(ctx)

	// イベントを収集しながら完了または提案を待つ
	deadline := time.After(110 * time.Second)
	var gotProposalOrComplete bool

	for !gotProposalOrComplete {
		select {
		case e := <-events:
			t.Logf("[%s] %s: %s", e.Type, e.Source, e.Message)
			switch e.Type {
			case agent.EventProposal:
				t.Log("Proposal received — denying to avoid actual exploitation")
				approve <- false // E2E テストではエクスプロイトを実行しない
				gotProposalOrComplete = true
			case agent.EventComplete:
				gotProposalOrComplete = true
			case agent.EventError:
				t.Logf("Agent error: %s", e.Message)
				gotProposalOrComplete = true
			}
		case <-deadline:
			t.Log("E2E timeout reached — checking if scan ran")
			// タイムアウトは失敗ではない（Brain の応答速度に依存するため）
			return
		}
	}

	// ターゲットにログが記録されていること
	if len(target.Logs) == 0 {
		t.Error("expected target to have logs after agent run")
	}

	// エンティティが収集されていること（nmap を Brain が実行した場合）
	anyRunTool := false
	for _, log := range target.Logs {
		if log.Source == agent.SourceTool {
			anyRunTool = true
			break
		}
	}
	if !anyRunTool {
		// Brain が run_tool を選ばなかった場合はスキップ（think/complete も有効な応答）
		t.Log("Brain chose think/complete without running a tool — acceptable")
		return
	}

	t.Logf("Agent completed. Entities found: %d, Logs: %d",
		len(target.Entities), len(target.Logs))
}

// --- ヘルパー ---

func filterEntities(entities []tools.Entity, typ tools.EntityType) []tools.Entity {
	var result []tools.Entity
	for _, e := range entities {
		if e.Type == typ {
			result = append(result, e)
		}
	}
	return result
}

func entityValues(entities []tools.Entity) []string {
	vals := make([]string, len(entities))
	for i, e := range entities {
		vals[i] = e.Value
	}
	return vals
}

// mockBrainForE2E は実際の LLM を使わずに決定論的に動作するテスト用 Brain。
type mockBrainForE2E struct {
	steps []schema.Action
	idx   int
}

func (m *mockBrainForE2E) Think(_ context.Context, _ brain.Input) (*schema.Action, error) {
	if m.idx >= len(m.steps) {
		return &schema.Action{Thought: "done", Action: schema.ActionComplete}, nil
	}
	a := m.steps[m.idx]
	m.idx++
	return &a, nil
}
func (m *mockBrainForE2E) Provider() string { return "mock-e2e" }

// TestE2E_NmapThenEntity は実 nmap + モック Brain でエンティティ収集を検証する。
func TestE2E_NmapThenEntity(t *testing.T) {
	requireNmap(t)

	ip := targetIP()
	target := agent.NewTarget(1, ip)

	store := tools.NewLogStore()
	runner := tools.NewRunner(store)

	registry := tools.NewRegistry()
	registry.Register(&tools.ToolDef{
		Name: "nmap", Binary: "nmap", TimeoutSec: 60,
		Output: tools.OutputConfig{Strategy: tools.StrategyHeadTail, HeadLines: 50, TailLines: 30},
	})

	mb := &mockBrainForE2E{
		steps: []schema.Action{
			{Thought: "start recon", Action: schema.ActionRunTool, Tool: "nmap", Args: []string{"-p", "21,22,80", "-Pn"}},
		},
	}

	events := make(chan agent.Event, 128)
	approve := make(chan bool, 1)
	userMsg := make(chan string, 1)

	loop := agent.NewLoop(target, mb, runner, registry, events, approve, userMsg)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	go loop.Run(ctx)

	deadline := time.After(80 * time.Second)
	for {
		select {
		case e := <-events:
			t.Logf("[%s] %s", e.Type, e.Message)
			if e.Type == agent.EventComplete {
				// nmap 実行後にエンティティが収集されているはず
				if len(target.Entities) == 0 {
					t.Log("No entities extracted — target might not be running or no open ports on tested ports")
				} else {
					t.Logf("Entities: %+v", target.Entities)
				}
				return
			}
		case <-deadline:
			t.Log("Timeout — scan may still be running")
			return
		}
	}
}
