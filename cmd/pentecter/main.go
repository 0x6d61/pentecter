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
	"github.com/0x6d61/pentecter/internal/memory"
	"github.com/0x6d61/pentecter/internal/skills"
	"github.com/0x6d61/pentecter/internal/tools"
	"github.com/0x6d61/pentecter/internal/tui"
)

func main() {
	var (
		provider = flag.String("provider", "anthropic", "LLM プロバイダー: anthropic, openai, ollama")
		model    = flag.String("model", "", "モデル名（省略時はプロバイダーのデフォルト）")
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
  ANTHROPIC_API_KEY     Anthropic API キー
  ANTHROPIC_AUTH_TOKEN  Claude Code OAuth トークン (claude auth token)
  OPENAI_API_KEY        OpenAI API キー
  OLLAMA_BASE_URL       Ollama サーバー URL (default: http://localhost:11434)
  OLLAMA_MODEL          Ollama モデル名 (default: llama3.2)

Examples:
  pentecter                                          # ターゲットなし起動（チャットで追加）
  pentecter 10.0.0.5                                 # ターゲット指定で起動
  pentecter -provider ollama 10.0.0.5 10.0.0.8       # 複数ターゲット

Chat commands:
  10.0.0.5             IP アドレスを入力してターゲット追加
  /target example.com  ドメインをターゲット追加
  /web-recon           スキル実行（skills/ ディレクトリから自動ロード）
`)
	}
	flag.Parse()

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
	if err := registry.LoadDir("tools"); err != nil {
		fmt.Fprintf(os.Stderr, "ツールロードエラー: %v\n", err)
		os.Exit(1)
	}

	// --- Blacklist ---
	blacklist := loadBlacklist("config/blacklist.yaml")

	// --- Skills ---
	skillsReg := skills.NewRegistry()
	_ = skillsReg.LoadDir("skills")

	// --- Memory ---
	memoryStore := memory.NewStore("memory")

	// --- CommandRunner ---
	logStore := tools.NewLogStore()
	runner := tools.NewCommandRunner(registry, blacklist, logStore)

	// --- Agent Team ---
	events := make(chan agent.Event, 512)
	approveMap := make(map[int]chan<- bool)
	userMsgMap := make(map[int]chan<- string)

	team := agent.NewTeam(agent.TeamConfig{
		Events:      events,
		Brain:       br,
		Runner:      runner,
		SkillsReg:   skillsReg,
		MemoryStore: memoryStore,
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

// loadBlacklist は YAML ファイルからブラックリストパターンを読み込む。
// ファイルが存在しない場合はデフォルトの安全パターンを返す。
func loadBlacklist(path string) *tools.Blacklist {
	data, err := os.ReadFile(path)
	if err != nil {
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
