package tui

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/0x6d61/pentecter/internal/brain"
)

// handleCommand processes slash commands. Returns true if the command was handled.
func (a *App) handleCommand(fullText string) bool {
	fields := strings.Fields(fullText)
	if len(fields) == 0 {
		return false
	}
	cmd := fields[0]

	switch cmd {
	case "/approve":
		a.handleApproveCommand(fullText)
		return true
	case "/model":
		a.handleModelCommand(fullText)
		return true
	case "/targets":
		a.handleTargetsCommand()
		return true
	case "/attackdata":
		a.handleAttackDataCommand()
		return true
	case "/skip-recon":
		a.handleSkipReconCommand()
		return true
	case "/fold":
		a.toggleFold()
		return true
	case "/status":
		a.printStatusLine()
		return true
	case "/copy":
		a.handleCopyCommand()
		return true
	default:
		return false
	}
}

// handleApproveCommand processes /approve commands.
func (a *App) handleApproveCommand(_ string) {
	if a.Runner == nil {
		a.logSystem("Auto-approve not available")
		return
	}

	currentStatus := "OFF"
	if a.Runner.AutoApprove() {
		currentStatus = "ON"
	}
	a.showSelect(
		fmt.Sprintf("Auto-approve (current: %s):", currentStatus),
		[]SelectOption{
			{Label: "ON  -- auto-approve all commands", Value: "on"},
			{Label: "OFF -- require approval", Value: "off"},
		},
		func(a *App, value string) {
			if a.Runner == nil {
				return
			}
			switch value {
			case "on":
				a.Runner.SetAutoApprove(true)
				a.logSystem("Auto-approve: ON -- all commands will execute without confirmation")
			case "off":
				a.Runner.SetAutoApprove(false)
				a.logSystem("Auto-approve: OFF -- proposals will require confirmation")
			}
		},
	)
}

func parseModelArg(fullText string) string {
	fields := strings.Fields(fullText)
	if len(fields) < 2 {
		return ""
	}
	return strings.TrimSpace(strings.Join(fields[1:], " "))
}

func modelOptionsFromOpenRouter(models []brain.OpenRouterModel) []SelectOption {
	opts := make([]SelectOption, 0, len(models))
	for _, m := range models {
		label := m.ID
		if m.Name != "" && !strings.EqualFold(m.Name, m.ID) {
			label = fmt.Sprintf("%s (%s)", m.ID, m.Name)
		}
		opts = append(opts, SelectOption{Label: label, Value: m.ID})
	}
	return opts
}

func resolveOpenRouterModel(query string, models []brain.OpenRouterModel) (string, bool) {
	q := strings.TrimSpace(query)
	if len(q) > len("openrouter/") && strings.HasPrefix(strings.ToLower(q), "openrouter/") {
		q = strings.TrimSpace(q[len("openrouter/"):])
	}
	if q == "" {
		return "", false
	}
	for _, m := range models {
		if strings.EqualFold(m.ID, q) {
			return m.ID, true
		}
	}
	return "", false
}

func filterOpenRouterModels(query string, models []brain.OpenRouterModel) []brain.OpenRouterModel {
	q := strings.TrimSpace(query)
	if len(q) > len("openrouter/") && strings.HasPrefix(strings.ToLower(q), "openrouter/") {
		q = strings.TrimSpace(q[len("openrouter/"):])
	}
	q = strings.ToLower(q)
	if q == "" {
		return models
	}
	filtered := make([]brain.OpenRouterModel, 0, len(models))
	for _, m := range models {
		if strings.Contains(strings.ToLower(m.ID), q) || strings.Contains(strings.ToLower(m.Name), q) {
			filtered = append(filtered, m)
		}
	}
	return filtered
}

func (a *App) fetchOpenRouterModels(ctx context.Context) ([]brain.OpenRouterModel, error) {
	if a.OpenRouterModelFetcher != nil {
		return a.OpenRouterModelFetcher(ctx)
	}
	return brain.FetchOpenRouterModels(ctx)
}

func (a *App) showOpenRouterModelSelect(query string) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	models, err := a.fetchOpenRouterModels(ctx)
	if err != nil {
		a.logSystem(fmt.Sprintf("Failed to fetch OpenRouter models: %v", err))
		return
	}
	if len(models) == 0 {
		a.logSystem("No models returned by OpenRouter.")
		return
	}

	if query != "" {
		if exact, ok := resolveOpenRouterModel(query, models); ok {
			a.switchModel(brain.ProviderOpenRouter, exact)
			return
		}
		models = filterOpenRouterModels(query, models)
		if len(models) == 0 {
			a.logSystem(fmt.Sprintf("No OpenRouter model matches: %s", query))
			return
		}
	}

	a.showSelect(
		fmt.Sprintf("Select model (%s, %d):", brain.ProviderOpenRouter, len(models)),
		modelOptionsFromOpenRouter(models),
		func(a *App, modelValue string) {
			a.switchModel(brain.ProviderOpenRouter, modelValue)
		},
	)
}

// modelsForProvider returns a list of models for the given provider.
func modelsForProvider(p brain.Provider) []SelectOption {
	switch p {
	case brain.ProviderAnthropic:
		return []SelectOption{
			{Label: "claude-sonnet-4-6 (recommended)", Value: "claude-sonnet-4-6"},
			{Label: "claude-opus-4-6", Value: "claude-opus-4-6"},
			{Label: "claude-haiku-4-5", Value: "claude-haiku-4-5-20251001"},
		}
	case brain.ProviderOpenAI:
		return []SelectOption{
			{Label: "gpt-4o (recommended)", Value: "gpt-4o"},
			{Label: "gpt-4o-mini", Value: "gpt-4o-mini"},
			{Label: "o3-mini", Value: "o3-mini"},
		}
	case brain.ProviderOllama:
		return []SelectOption{
			{Label: "llama3.2 (recommended)", Value: "llama3.2"},
			{Label: "llama3.2:3b", Value: "llama3.2:3b"},
			{Label: "qwen2.5:7b", Value: "qwen2.5:7b"},
			{Label: "gemma2:9b", Value: "gemma2:9b"},
		}
	default:
		return nil
	}
}

// handleModelCommand processes /model commands.
func (a *App) handleModelCommand(fullText string) {
	detected := brain.DetectAvailableProviders()
	if len(detected) == 0 {
		a.logSystem("No providers detected. Set ANTHROPIC_API_KEY or CLAUDE_CODE_OAUTH_TOKEN (or ANTHROPIC_OAUTH_TOKEN), OPENAI_API_KEY, OPENROUTER_API_KEY, or OLLAMA_BASE_URL.")
		return
	}
	query := parseModelArg(fullText)

	if len(detected) == 1 && detected[0] == brain.ProviderOpenRouter {
		a.showOpenRouterModelSelect(query)
		return
	}

	options := make([]SelectOption, len(detected))
	for i, p := range detected {
		options[i] = SelectOption{
			Label: string(p),
			Value: string(p),
		}
	}

	a.showSelect(
		"Select provider:",
		options,
		func(a *App, providerValue string) {
			provider := brain.Provider(providerValue)
			if provider == brain.ProviderOpenRouter {
				a.showOpenRouterModelSelect(query)
				return
			}
			models := modelsForProvider(provider)
			if len(models) == 0 {
				a.switchModel(provider, "")
				return
			}
			a.showSelect(
				fmt.Sprintf("Select model (%s):", providerValue),
				models,
				func(a *App, modelValue string) {
					a.switchModel(provider, modelValue)
				},
			)
		},
	)
}

// switchModel executes the actual model switch via BrainFactory.
func (a *App) switchModel(provider brain.Provider, model string) {
	if a.BrainFactory == nil {
		a.logSystem("Model switching not available (no brain factory)")
		return
	}

	newBrain, err := a.BrainFactory(brain.ConfigHint{
		Provider: provider,
		Model:    model,
	})
	if err != nil {
		a.logSystem(fmt.Sprintf("Failed to switch model: %v", err))
		return
	}

	if a.team != nil {
		a.team.SetBrain(newBrain)
	}
	a.CurrentProvider = string(provider)
	a.CurrentModel = model
	msg := fmt.Sprintf("Switched to %s", provider)
	if model != "" {
		msg += "/" + model
	}
	a.logSystem(msg)
}

// handleTargetsCommand shows a target list for selection.
func (a *App) handleTargetsCommand() {
	if len(a.targets) == 0 {
		a.logSystem("No targets. Add one with /target <host>")
		return
	}

	options := make([]SelectOption, len(a.targets))
	for i, t := range a.targets {
		status := t.GetStatus()
		icon := status.Icon()
		label := fmt.Sprintf("%s %s [%s]", icon, t.Host, status)
		options[i] = SelectOption{
			Label: label,
			Value: fmt.Sprintf("%d", i),
		}
	}

	a.showSelect(
		"Select target:",
		options,
		func(a *App, value string) {
			idx, err := strconv.Atoi(value)
			if err != nil {
				return
			}
			a.mu.Lock()
			if idx < 0 || idx >= len(a.targets) {
				a.mu.Unlock()
				return
			}
			a.selected = idx
			host := a.targets[idx].Host
			a.outputScroll = 0
			a.outputFollow = true
			a.outputPrevWrapped = 0
			a.outputPrevWrapWidth = 0
			if a.targets[idx].GetProposal() != nil {
				a.inputMode = ModeProposal
			} else if a.inputMode == ModeProposal {
				a.inputMode = ModeNormal
			}
			a.mu.Unlock()

			a.clearAndReprint()
			a.refreshPrompt()
			a.logSystem(fmt.Sprintf("Switched to target: %s", host))
		},
	)
}

// handleAttackDataCommand displays the attack data tree for the active target.
func (a *App) handleAttackDataCommand() {
	if a.selected < 0 || a.selected >= len(a.targets) {
		a.logSystem("No target selected.")
		return
	}
	target := a.targets[a.selected]
	rt := target.GetAttackData()
	if rt == nil {
		a.logSystem("No attack data tree available for this target.")
		return
	}
	output := rt.RenderTree()
	a.printAttackData(target.Host, output)
}

// handleSkipReconCommand unlocks the RECON phase for the active target.
func (a *App) handleSkipReconCommand() {
	if a.selected < 0 || a.selected >= len(a.targets) {
		a.logSystem("No target selected.")
		return
	}
	target := a.targets[a.selected]
	rt := target.GetAttackData()
	if rt == nil {
		a.logSystem("No attack data tree available for this target.")
		return
	}
	if !rt.IsLocked() {
		a.logSystem("RECON phase is already unlocked.")
		return
	}
	pending := rt.CountPending()
	rt.Unlock()
	a.logSystem(fmt.Sprintf("RECON phase unlocked (%d pending tasks skipped). Agent will proceed to ANALYZE.", pending))
}

// handleCopyCommand enters log copy mode.
func (a *App) handleCopyCommand() {
	a.mu.Lock()
	a.enterCopyModeLocked()
	a.mu.Unlock()
}
