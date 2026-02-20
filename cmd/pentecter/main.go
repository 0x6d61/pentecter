package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/joho/godotenv"

	"github.com/0x6d61/pentecter/internal/agent"
	"github.com/0x6d61/pentecter/internal/brain"
	"github.com/0x6d61/pentecter/internal/config"
	"github.com/0x6d61/pentecter/internal/knowledge"
	"github.com/0x6d61/pentecter/internal/mcp"
	"github.com/0x6d61/pentecter/internal/memory"
	"github.com/0x6d61/pentecter/internal/skills"
	"github.com/0x6d61/pentecter/internal/tools"
	"github.com/0x6d61/pentecter/internal/tui"
)

func main() {
	// Load .env file if present (ignored if not found)
	_ = godotenv.Load()

	var (
		provider    = flag.String("provider", "", "LLM provider: anthropic, openai, ollama (auto-detect if empty)")
		model       = flag.String("model", "", "Model name (default: provider's default)")
		autoApprove = flag.Bool("auto-approve", false, "Auto-approve all commands without proposal")
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `⚡ Pentecter — Autonomous Penetration Testing Agent

Usage:
  pentecter [flags] [target-ip...]

Flags:
`)
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
Environment:
  ANTHROPIC_API_KEY          Anthropic API key
  CLAUDE_CODE_OAUTH_TOKEN    Claude Code OAuth token (claude setup-token)
  OPENAI_API_KEY        OpenAI API key
  OLLAMA_BASE_URL       Ollama server URL (default: http://localhost:11434)
  OLLAMA_MODEL          Ollama model name (default: llama3.2)

Examples:
  pentecter                                          # Start without targets (add via chat)
  pentecter 10.0.0.5                                 # Start with a target
  pentecter -provider ollama 10.0.0.5 10.0.0.8       # Multiple targets

Chat commands:
  10.0.0.5             Enter an IP address to add a target
  /target example.com  Add a domain as target
  /web-recon           Run a skill (auto-loaded from skills/ directory)
`)
	}
	flag.Parse()

	// --- Brain ---
	// Auto-detect provider if not specified
	selectedProvider := brain.Provider(*provider)
	if *provider == "" {
		detected := brain.DetectAvailableProviders()
		if len(detected) == 0 {
			fmt.Fprintln(os.Stderr, "No LLM provider detected. Set one of:")
			fmt.Fprintln(os.Stderr, "  ANTHROPIC_API_KEY, CLAUDE_CODE_OAUTH_TOKEN, OPENAI_API_KEY, or OLLAMA_BASE_URL")
			os.Exit(1)
		}
		selectedProvider = detected[0]
		fmt.Fprintf(os.Stderr, "Auto-detected provider: %s\n", selectedProvider)
	}

	// --- Tools ---（Brain より先にロードし、ツール名をシステムプロンプトに注入する）
	registry := tools.NewRegistry()
	if err := registry.LoadDir("tools"); err != nil {
		fmt.Fprintf(os.Stderr, "tool load error: %v\n", err)
		os.Exit(1)
	}

	// Registry からツール名を収集
	var toolNames []string
	for _, def := range registry.All() {
		toolNames = append(toolNames, def.Name)
	}

	// --- MCP ---
	mcpMgr, mcpErr := mcp.NewManager("config/mcp.yaml")
	if mcpErr != nil {
		fmt.Fprintf(os.Stderr, "MCP config warning: %v\n", mcpErr)
	}

	brainCfg, err := brain.LoadConfig(brain.ConfigHint{
		Provider: selectedProvider,
		Model:    *model,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "brain config error:", err)
		os.Exit(1)
	}
	brainCfg.ToolNames = toolNames

	// MCP ツールスキーマを Brain に注入
	if mcpMgr != nil {
		if err := mcpMgr.StartAll(context.Background()); err != nil {
			fmt.Fprintf(os.Stderr, "MCP start warning: %v\n", err)
		}
		defer func() { _ = mcpMgr.Close() }()
		for _, t := range mcpMgr.ListAllTools() {
			brainCfg.MCPTools = append(brainCfg.MCPTools, brain.MCPToolInfo{
				Server:      t.Server,
				Name:        t.Name,
				Description: t.Description,
				InputSchema: t.InputSchema,
			})
		}
	}

	br, err := brain.New(brainCfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "brain init error:", err)
		os.Exit(1)
	}

	// --- SubBrain for SmartSubAgent ---
	// Defaults to same config as main brain; override with SUBAGENT_MODEL / SUBAGENT_PROVIDER.
	// IsSubAgent = true により SubAgent 用のシンプルなプロンプトが使われる
	// （spawn_task 等の無限ループを防ぐ）。
	subBrainCfg := brainCfg // copy main config
	subBrainCfg.IsSubAgent = true
	if model := os.Getenv("SUBAGENT_MODEL"); model != "" {
		subBrainCfg.Model = model
	}
	if provider := os.Getenv("SUBAGENT_PROVIDER"); provider != "" {
		subBrainCfg.Provider = brain.Provider(provider)
		// Reload config for the new provider
		reloaded, err := brain.LoadConfig(brain.ConfigHint{
			Provider: brain.Provider(provider),
			Model:    subBrainCfg.Model,
		})
		if err == nil {
			subBrainCfg = reloaded
			subBrainCfg.ToolNames = toolNames
			subBrainCfg.IsSubAgent = true
		}
	}
	subBrain, err := brain.New(subBrainCfg)
	if err != nil {
		// SubBrain creation failed — continue without SmartSubAgent
		log.Printf("SubBrain creation failed (SmartSubAgent disabled): %v", err)
		subBrain = nil
	}

	// --- App Config (knowledge + blacklist) ---
	appCfg, cfgErr := config.Load("config/config.yaml")
	if cfgErr != nil {
		fmt.Fprintf(os.Stderr, "Config warning: %v\n", cfgErr)
		appCfg = &config.AppConfig{}
	}

	// --- Blacklist ---
	blacklist := tools.NewBlacklist(appCfg.Blacklist)
	if len(appCfg.Blacklist) == 0 {
		// デフォルトの安全パターン
		blacklist = tools.NewBlacklist([]string{
			`rm\s+-rf\s+/`,
			`dd\s+if=`,
			`mkfs`,
			`\bshutdown\b`,
			`\breboot\b`,
		})
	}

	// --- Skills ---
	skillsReg := skills.NewRegistry()
	_ = skillsReg.LoadDir("skills")

	// --- Knowledge Base ---
	var knowledgeStore *knowledge.Store
	if len(appCfg.Knowledge) > 0 {
		// 最初のエントリを使用（将来的に複数対応可能）
		entry := appCfg.Knowledge[0]
		ks := knowledge.NewStore(entry.Path)
		if ks != nil {
			knowledgeStore = ks
			log.Printf("Knowledge base loaded: %s (%s)", entry.Name, entry.Path)
		} else {
			log.Printf("Knowledge base path not found: %s (run: git clone --depth 1 https://github.com/carlospolop/hacktricks.git)", entry.Path)
		}
	}

	// --- Memory ---
	memoryStore := memory.NewStore("memory")

	// --- CommandRunner ---
	logStore := tools.NewLogStore()
	runner := tools.NewCommandRunner(registry, blacklist, logStore)
	if *autoApprove {
		runner.SetAutoApprove(true)
	}

	// --- Agent Team ---
	events := make(chan agent.Event, 512)
	approveMap := make(map[int]chan<- bool)
	userMsgMap := make(map[int]chan<- string)

	team := agent.NewTeam(agent.TeamConfig{
		Events:      events,
		Brain:       br,
		SubBrain:    subBrain,
		Runner:      runner,
		SkillsReg:   skillsReg,
		MemoryStore: memoryStore,
		MCPManager:     mcpMgr,
		KnowledgeStore: knowledgeStore,
	})

	// CLI ターゲットを事前追加
	var targets []*agent.Target
	for _, ip := range flag.Args() {
		target, approveCh, userMsgCh := team.AddTarget(ip)
		targets = append(targets, target)
		approveMap[target.ID] = approveCh
		userMsgMap[target.ID] = userMsgCh
	}

	// --- TUI ---
	m := tui.NewWithTargets(targets)
	m.ConnectTeam(team, events, approveMap, userMsgMap)

	// Connect CommandRunner for /approve command
	m.Runner = runner

	// BrainFactory for /model command
	m.BrainFactory = func(hint brain.ConfigHint) (brain.Brain, error) {
		cfg, err := brain.LoadConfig(hint)
		if err != nil {
			return nil, err
		}
		cfg.ToolNames = toolNames
		return brain.New(cfg)
	}

	// グレースフルシャットダウン
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Agent Team を起動
	team.Start(ctx)

	// TUI を起動（ブロッキング）
	p := tea.NewProgram(m, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "TUI error:", err)
		os.Exit(1)
	}
}
