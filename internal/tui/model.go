// Package tui implements the Bubble Tea TUI for Pentecter.
package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/0x6d61/pentecter/internal/agent"
	"github.com/0x6d61/pentecter/internal/brain"
	"github.com/0x6d61/pentecter/internal/tools"
)

// FocusState tracks which pane has keyboard focus.
type FocusState int

const (
	FocusList     FocusState = iota // left pane: target list
	FocusViewport                   // right pane: session log
	FocusInput                      // bottom: input bar
)

// leftPaneOuterWidth is the total rendered width of the left pane (borders included).
const leftPaneOuterWidth = 32

// AgentEventMsg は Agent ループから届く Bubble Tea メッセージ。
type AgentEventMsg agent.Event

// Model is the root Bubble Tea model for the Pentecter Commander Console.
type Model struct {
	width    int
	height   int
	ready    bool
	focus    FocusState
	targets  []*agent.Target
	selected int // index into targets
	list     list.Model
	viewport viewport.Model
	input    textinput.Model

	// Agent チームとの通信チャネル（nil = デモモード）
	team           *agent.Team              // 動的ターゲット追加用（nil = デモモード）
	agentEvents    <-chan agent.Event        // 全 Agent → TUI（TargetID で識別）
	agentApproveMap map[int]chan<- bool      // targetID → approve チャネル
	agentUserMsgMap map[int]chan<- string    // targetID → userMsg チャネル

	// BrainFactory creates a new Brain from a ConfigHint (for /model command).
	BrainFactory func(brain.ConfigHint) (brain.Brain, error)

	// Runner is the CommandRunner used for /approve command (auto-approve toggle).
	Runner *tools.CommandRunner
}

// AgentEventCmd は次の Agent イベントを待つ Bubble Tea コマンド。
func AgentEventCmd(ch <-chan agent.Event) tea.Cmd {
	return func() tea.Msg {
		return AgentEventMsg(<-ch)
	}
}

// targetListItem wraps *agent.Target to satisfy the list.Item interface.
type targetListItem struct {
	t *agent.Target
}

func (i targetListItem) Title() string {
	icon := i.t.Status.Icon()
	var coloredIcon string
	switch i.t.Status {
	case agent.StatusPwned:
		coloredIcon = statusPwnedStyle.Render(icon)
	case agent.StatusRunning:
		coloredIcon = statusRunningStyle.Render(icon)
	case agent.StatusScanning:
		coloredIcon = statusScanningStyle.Render(icon)
	case agent.StatusPaused:
		coloredIcon = statusPausedStyle.Render(icon)
	case agent.StatusFailed:
		coloredIcon = statusFailedStyle.Render(icon)
	default:
		coloredIcon = statusIdleStyle.Render(icon)
	}
	return fmt.Sprintf("%s %s", coloredIcon, i.t.Host)
}

func (i targetListItem) Description() string {
	extra := ""
	if i.t.Proposal != nil {
		extra = lipgloss.NewStyle().Foreground(colorWarning).Render(" ⚠ APPROVAL")
	}
	return fmt.Sprintf("[%s]%s", i.t.Status, extra)
}

func (i targetListItem) FilterValue() string { return i.t.Host }

// New はデモデータで Model を初期化する（開発・デモ用）。
// 本番では NewWithTargets を使うこと。
func New() Model {
	return NewWithTargets(buildDemoTargets())
}

// NewWithTargets は指定されたターゲットリストで Model を初期化する。
func NewWithTargets(targets []*agent.Target) Model {
	items := make([]list.Item, len(targets))
	for i, t := range targets {
		items[i] = targetListItem{t: t}
	}

	d := list.NewDefaultDelegate()
	d.ShowDescription = true
	d.Styles.SelectedTitle = d.Styles.SelectedTitle.Foreground(colorPrimary)
	d.Styles.SelectedDesc = d.Styles.SelectedDesc.Foreground(colorSecondary)

	l := list.New(items, d, leftPaneOuterWidth-4, 20)
	l.Title = "TARGETS"
	l.SetShowHelp(false)
	l.SetFilteringEnabled(false)
	l.Styles.Title = lipgloss.NewStyle().
		Foreground(colorTitle).
		Bold(true).
		Padding(0, 1)

	ti := textinput.New()
	ti.Placeholder = "Chat with AI or enter command..."
	ti.CharLimit = 500
	ti.Focus() // Start with input focused

	return Model{
		targets:         targets,
		selected:        0,
		list:            l,
		input:           ti,
		focus:           FocusInput,
		agentApproveMap: make(map[int]chan<- bool),
		agentUserMsgMap: make(map[int]chan<- string),
	}
}

// Init implements tea.Model.
func (m Model) Init() tea.Cmd {
	if m.agentEvents != nil {
		return AgentEventCmd(m.agentEvents)
	}
	return nil
}

// ConnectTeam は Agent Team を TUI に接続する。
// team: 動的ターゲット追加に使用
// events: 全エージェントのイベント（TargetID で識別）
// approveMap: targetID → approve チャネル
// userMsgMap: targetID → userMsg チャネル
func (m *Model) ConnectTeam(
	team *agent.Team,
	events <-chan agent.Event,
	approveMap map[int]chan<- bool,
	userMsgMap map[int]chan<- string,
) {
	m.team = team
	m.agentEvents = events
	m.agentApproveMap = approveMap
	m.agentUserMsgMap = userMsgMap
}

// activeTarget returns the currently selected target, or nil if none.
func (m *Model) activeTarget() *agent.Target {
	if m.selected < 0 || m.selected >= len(m.targets) {
		return nil
	}
	return m.targets[m.selected]
}

// rebuildViewport regenerates the viewport content for the active target,
// including any pending proposal at the bottom.
func (m *Model) rebuildViewport() {
	t := m.activeTarget()
	if t == nil {
		m.viewport.SetContent("  No target selected.\n\n  Add a target by entering an IP address:\n    e.g. 10.0.0.5 / /target example.com\n\n  Skills: /web-recon, /full-scan, /sqli-check")
		return
	}

	var sb strings.Builder

	header := lipgloss.NewStyle().
		Foreground(colorPrimary).
		Bold(true).
		Render(fmt.Sprintf("═══ Session: %s [%s] ═══", t.Host, t.Status))
	sb.WriteString(header + "\n\n")

	for _, entry := range t.Logs {
		ts := lipgloss.NewStyle().Foreground(colorMuted).Render(entry.Time.Format("15:04:05"))

		var srcLabel string
		switch entry.Source {
		case agent.SourceAI:
			srcLabel = sourceAIStyle.Render("[AI  ]")
		case agent.SourceTool:
			srcLabel = sourceToolStyle.Render("[TOOL]")
		case agent.SourceSystem:
			srcLabel = sourceSysStyle.Render("[SYS ]")
		case agent.SourceUser:
			srcLabel = sourceUserStyle.Render("[USER]")
		default:
			srcLabel = fmt.Sprintf("[%s]", entry.Source)
		}

		fmt.Fprintf(&sb, "%s %s  %s\n", ts, srcLabel, entry.Message)
	}

	// Render pending proposal at the bottom of the session log.
	if p := t.Proposal; p != nil {
		sb.WriteString("\n")

		proposalTitle := lipgloss.NewStyle().
			Foreground(colorWarning).
			Bold(true).
			Render("⚠  PROPOSAL — Awaiting approval")

		proposalBody := fmt.Sprintf(
			"%s\n  Tool: %s %s",
			p.Description,
			p.Tool,
			strings.Join(p.Args, " "),
		)

		proposalControls := lipgloss.NewStyle().
			Foreground(colorMuted).
			Render("  [y] Approve  [n] Reject  [e] Edit")

		boxWidth := m.viewport.Width - 2
		if boxWidth < 10 {
			boxWidth = 10
		}

		box := proposalBoxStyle.Width(boxWidth).Render(
			proposalTitle + "\n\n  " + proposalBody + "\n\n" + proposalControls,
		)
		sb.WriteString(box + "\n")
	}

	m.viewport.SetContent(sb.String())
	m.viewport.GotoBottom()
}

// syncListItems refreshes list items to reflect the current target states.
func (m *Model) syncListItems() {
	items := make([]list.Item, len(m.targets))
	for i, t := range m.targets {
		items[i] = targetListItem{t: t}
	}
	m.list.SetItems(items)
}

// buildDemoTargets creates representative demo targets for Phase 1 display.
func buildDemoTargets() []*agent.Target {
	t1 := agent.NewTarget(1, "10.0.0.5")
	t1.Status = agent.StatusScanning
	t1.AddLog(agent.SourceSystem, "Session started")
	t1.AddLog(agent.SourceAI, "Starting recon on 10.0.0.5")
	t1.AddLog(agent.SourceTool, "nmap -sV -p- 10.0.0.5")
	t1.AddLog(agent.SourceTool, "PORT     STATE  SERVICE  VERSION")
	t1.AddLog(agent.SourceTool, "22/tcp   open   ssh      OpenSSH 8.0")
	t1.AddLog(agent.SourceTool, "80/tcp   open   http     Apache httpd 2.4.49")
	t1.AddLog(agent.SourceAI, "Detected Apache 2.4.49 — possible CVE-2021-41773 (Path Traversal)")

	t2 := agent.NewTarget(2, "10.0.0.8")
	t2.AddLog(agent.SourceSystem, "Session started")
	t2.AddLog(agent.SourceAI, "Starting recon on 10.0.0.8")
	t2.AddLog(agent.SourceTool, "nmap -sV 10.0.0.8")
	t2.AddLog(agent.SourceTool, "80/tcp open http Apache httpd 2.4.49")
	t2.AddLog(agent.SourceAI, "Port 80 (Apache 2.4.49) — vulnerable to CVE-2021-41773")
	t2.AddLog(agent.SourceAI, "Planning exploit with Metasploit module...")
	// Simulate AI proposing an exploit
	t2.Logs[len(t2.Logs)-1].Time = time.Now()
	t2.SetProposal(&agent.Proposal{
		Description: "Exploit Apache 2.4.49 Path Traversal (CVE-2021-41773)",
		Tool:        "metasploit",
		Args:        []string{"exploit/multi/http/apache_normalize_path_rce", "--target", "10.0.0.8", "--lhost", "10.0.0.2"},
	})

	t3 := agent.NewTarget(3, "10.0.0.12")
	t3.AddLog(agent.SourceSystem, "Session started")

	return []*agent.Target{t1, t2, t3}
}
