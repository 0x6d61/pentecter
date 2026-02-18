package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	tea "github.com/charmbracelet/bubbletea"
	"gopkg.in/yaml.v3"

	"github.com/0x6d61/pentecter/internal/agent"
	"github.com/0x6d61/pentecter/internal/brain"
	"github.com/0x6d61/pentecter/internal/tools"
	"github.com/0x6d61/pentecter/internal/tui"
)

func main() {
	var (
		provider = flag.String("provider", "anthropic", "LLM プロバイダー: anthropic, openai, ollama")
		model    = flag.String("model", "", "モデル名（省略時はプロバイダーのデフォルト）")
		toolDir  = flag.String("tools", "tools", "ツール定義 YAML ディレクトリ")
		noDemo   = flag.Bool("no-demo", false, "デモデータなしで起動する")
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `⚡ Pentecter — Autonomous Penetration Testing Agent

Usage:
  pentecter [flags] <target-ip> [target-ip...]

Flags:
`)
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
Environment:
  ANTHROPIC_API_KEY     Anthropic API キー
  ANTHROPIC_AUTH_TOKEN  Claude Code OAuth トークン (claude auth token)
  OPENAI_API_KEY        OpenAI API キー
  OLLAMA_BASE_URL       Ollama サーバー URL (default: http://localhost:11434)
  OLLAMA_MODEL          Ollama モデル名 (default: llama3.2)

Examples:
  pentecter 10.0.0.5
  pentecter -provider ollama 10.0.0.5 10.0.0.8
  pentecter -provider anthropic -model claude-sonnet-4-6 192.168.1.1
`)
	}
	flag.Parse()

	targetIPs := flag.Args()

	// ターゲットなし → デモモード
	if len(targetIPs) == 0 && !*noDemo {
		runDemo()
		return
	}

	if len(targetIPs) == 0 {
		fmt.Fprintln(os.Stderr, "エラー: ターゲット IP を指定してください")
		flag.Usage()
		os.Exit(1)
	}

	// --- Brain ---
	brainCfg, err := brain.LoadConfig(brain.ConfigHint{
		Provider: brain.Provider(*provider),
		Model:    *model,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "Brain 設定エラー:", err)
		os.Exit(1)
	}

	br, err := brain.New(brainCfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Brain 初期化エラー:", err)
		os.Exit(1)
	}

	// --- Tools ---
	registry := tools.NewRegistry()
	if err := registry.LoadDir(*toolDir); err != nil {
		fmt.Fprintf(os.Stderr, "ツールロードエラー (%s): %v\n", *toolDir, err)
		os.Exit(1)
	}
	// MCP サーバー設定は将来実装（現在は YAML ベースのみ）

	// --- Blacklist ---
	blacklist := loadBlacklist("config/blacklist.yaml")

	// --- CommandRunner ---
	store := tools.NewLogStore()
	runner := tools.NewCommandRunner(registry, blacklist, store)

	// --- Agent Team ---
	events := make(chan agent.Event, 512)
	approveMap := make(map[int]chan<- bool)
	userMsgMap := make(map[int]chan<- string)

	var targets []*agent.Target
	var loops []*agent.Loop

	for i, ip := range targetIPs {
		id := i + 1
		target := agent.NewTarget(id, ip)
		targets = append(targets, target)

		approveCh := make(chan bool, 1)
		userMsgCh := make(chan string, 4)
		approveMap[id] = approveCh
		userMsgMap[id] = userMsgCh

		loop := agent.NewLoop(target, br, runner, events, approveCh, userMsgCh)
		loops = append(loops, loop)
	}

	team := agent.NewTeam(events, loops...)

	// --- TUI ---
	m := tui.NewWithTargets(targets)
	m.ConnectTeam(events, approveMap, userMsgMap)

	// グレースフルシャットダウン
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Agent Team を起動
	team.Start(ctx)

	// TUI を起動（ブロッキング）
	p := tea.NewProgram(m, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "TUI エラー:", err)
		os.Exit(1)
	}
}

// runDemo はターゲット未指定時にデモモードで TUI を起動する。
func runDemo() {
	m := tui.New()
	p := tea.NewProgram(m, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "Pentecter エラー:", err)
		os.Exit(1)
	}
}

// loadBlacklist は YAML ファイルからブラックリストパターンを読み込む。
// ファイルが存在しない場合はデフォルトの安全パターンを返す。
func loadBlacklist(path string) *tools.Blacklist {
	data, err := os.ReadFile(path)
	if err != nil {
		// config/blacklist.yaml がなくても最低限のパターンを適用
		return tools.NewBlacklist([]string{
			`rm\s+-rf\s+/`,
			`dd\s+if=`,
			`mkfs`,
			`\bshutdown\b`,
			`\breboot\b`,
		})
	}

	var cfg struct {
		Patterns []string `yaml:"patterns"`
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		fmt.Fprintf(os.Stderr, "ブラックリスト読み込みエラー: %v（デフォルトを使用）\n", err)
		return tools.NewBlacklist(nil)
	}
	return tools.NewBlacklist(cfg.Patterns)
}
