// Package tui implements the Bubble Tea TUI for Pentecter.
package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textarea"
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
	FocusViewport FocusState = iota // main pane: session log
	FocusInput                      // bottom: input bar
)

// InputMode tracks whether the input bar is in normal text mode or select mode.
type InputMode int

const (
	InputNormal     InputMode = iota // normal text input
	InputSelect                      // interactive selection UI
	InputConfirmQuit                 // quit confirmation dialog
)

// SelectOption represents a single option in the select UI.
type SelectOption struct {
	Label string
	Value string
}

// AgentEventBatchMsg は Agent ループから届くバッチ化された Bubble Tea メッセージ。
// 1回の Cmd で最大 maxBatchSize 個のイベントを回収し、KeyMsg のスターベーションを防止する。
type AgentEventBatchMsg []agent.Event

// debounceMsg はビューポート再描画のデバウンスタイマー完了メッセージ。
type debounceMsg struct{}

const maxBatchSize = 50

// Model is the root Bubble Tea model for the Pentecter Commander Console.
type Model struct {
	width    int
	height   int
	ready    bool
	focus    FocusState
	targets  []*agent.Target
	selected int // index into targets
	viewport viewport.Model
	input    textarea.Model

	// Agent チームとの通信チャネル（nil = デモモード）
	team           *agent.Team              // 動的ターゲット追加用（nil = デモモード）
	agentEvents    <-chan agent.Event        // 全 Agent → TUI（TargetID で識別）
	agentApproveMap map[int]chan<- bool      // targetID → approve チャネル
	agentUserMsgMap map[int]chan<- string    // targetID → userMsg チャネル

	// BrainFactory creates a new Brain from a ConfigHint (for /model command).
	BrainFactory func(brain.ConfigHint) (brain.Brain, error)

	// Runner is the CommandRunner used for /approve command (auto-approve toggle).
	Runner *tools.CommandRunner

	// spinner はアニメーション付きスピナー（Thinking / SubTask ブロック用）。
	spinner  spinner.Model
	spinning bool // true の場合、アクティブな thinking/subtask ブロックが存在する

	// logsExpanded が true の場合、すべてのログ内容を折りたたまずに表示する。
	logsExpanded bool

	// viewportDirty が true の場合、次のスピナーティックまたはデバウンスタイマーでビューポートを再描画する。
	viewportDirty bool

	// Global system logs — shown when no target is active
	globalLogs []string

	// Current model info — displayed in status bar
	CurrentProvider string
	CurrentModel    string

	// Select mode fields — used by /model, /approve to show interactive selection.
	inputMode      InputMode
	selectOptions  []SelectOption
	selectIndex    int
	selectTitle    string
	selectCallback func(m *Model, value string)
}

// AgentEventCmd は Agent イベントをバッチで回収する Bubble Tea コマンド。
// 最初のイベントはブロッキングで待ち、その後は非ブロッキングで最大 maxBatchSize 個まで回収する。
// これにより KeyMsg が AgentEventMsg にスターブされるのを防止する。
func AgentEventCmd(ch <-chan agent.Event) tea.Cmd {
	return func() tea.Msg {
		first := <-ch
		batch := make([]agent.Event, 1, maxBatchSize)
		batch[0] = first
		for len(batch) < maxBatchSize {
			select {
			case e := <-ch:
				batch = append(batch, e)
			default:
				return AgentEventBatchMsg(batch)
			}
		}
		return AgentEventBatchMsg(batch)
	}
}

// NewWithTargets は指定されたターゲットリストで Model を初期化する。
func NewWithTargets(targets []*agent.Target) Model {
	ta := textarea.New()
	ta.Prompt = ""
	ta.Placeholder = "Type here... [Enter] send  [Alt+Enter] newline"
	ta.CharLimit = 2000
	ta.SetHeight(1)        // 初期高さ 1 行
	ta.MaxHeight = 3       // Ctrl+Enter で最大 3 行まで拡張
	ta.ShowLineNumbers = false
	ta.Focus()
	// Enter で送信（Update() で処理）、Alt+Enter で改行
	// 注意: bubbletea v1 は Ctrl 修飾キーを検出できないため Ctrl+Enter は使用不可
	ta.KeyMap.InsertNewline.SetKeys("alt+enter")

	// スピナー初期化（Braille dots: ⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏）
	sp := spinner.New()
	sp.Spinner = spinner.Dot
	sp.Style = lipgloss.NewStyle().Foreground(colorSecondary)

	return Model{
		targets:         targets,
		selected:        0,
		input:           ta,
		spinner:         sp,
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
// ユーザーが上にスクロールしている場合はスクロール位置を維持する（auto-scroll は底にいるときだけ）。
func (m *Model) rebuildViewport() {
	t := m.activeTarget()
	if t == nil {
		var sb strings.Builder
		sb.WriteString("  No target selected.\n\n")
		sb.WriteString("  Add a target by entering an IP address:\n")
		sb.WriteString("    e.g. 10.0.0.5 / /target example.com\n\n")
		sb.WriteString("  Commands: /targets, /model, /approve, /curl, /ssh\n")
		if len(m.globalLogs) > 0 {
			sb.WriteString("\n")
			for _, log := range m.globalLogs {
				sb.WriteString("  [SYS] " + log + "\n")
			}
		}
		m.viewport.SetContent(sb.String())
		return
	}

	vpWidth := m.viewport.Width
	if vpWidth <= 0 {
		vpWidth = 80 // fallback
	}

	// auto-scroll 判定: 現在底付近にいるかチェック（SetContent 前に取得）
	atBottom := m.viewport.AtBottom()

	// ブロックベースレンダリング（スピナーフレームを渡す）
	content := renderBlocks(t.Blocks, vpWidth, m.logsExpanded, m.spinner.View())

	// プロポーザルをビューポートの末尾に追加
	if p := t.GetProposal(); p != nil {
		content += m.renderProposal(p)
	}

	m.viewport.SetContent(content)
	// ユーザーが底にいるときだけ auto-scroll（上にスクロール中は位置を維持）
	if atBottom {
		m.viewport.GotoBottom()
	}
}

// renderProposal はプロポーザルボックスをレンダリングする。
func (m *Model) renderProposal(p *agent.Proposal) string {
	var sb strings.Builder
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

	return sb.String()
}

// showSelect activates the select UI with the given title, options, and callback.
// The callback is invoked when the user presses Enter on an option.
func (m *Model) showSelect(title string, options []SelectOption, callback func(m *Model, value string)) {
	m.inputMode = InputSelect
	m.selectOptions = options
	m.selectIndex = 0
	m.selectTitle = title
	m.selectCallback = callback
}

