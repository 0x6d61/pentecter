package tui

import (
	"context"
	"fmt"
	"os"
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
	case "/thinkfold":
		a.toggleThinkingFold()
		return true
	case "/status":
		a.printStatusLine()
		return true
	default:
		return false
	}
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
	q := strings.ToLower(strings.TrimSpace(query))
	if q == "" {
		return models
	}
	filtered := make([]brain.OpenRouterModel, 0, len(models))
	for _, m := range models {
		id := strings.ToLower(m.ID)
		name := strings.ToLower(m.Name)
		if strings.Contains(id, q) || strings.Contains(name, q) {
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

// handleModelCommand processes /model commands.
func (a *App) handleModelCommand(fullText string) {
	if os.Getenv("OPENROUTER_API_KEY") == "" {
		a.logSystem("No providers detected. Set OPENROUTER_API_KEY.")
		return
	}

	provider := brain.ProviderOpenRouter
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

	arg := parseModelArg(fullText)
	if arg != "" {
		if exact, ok := resolveOpenRouterModel(arg, models); ok {
			a.switchModel(provider, exact)
			return
		}
		filtered := filterOpenRouterModels(arg, models)
		if len(filtered) == 0 {
			a.logSystem(fmt.Sprintf("No OpenRouter model matches: %s", arg))
			return
		}
		a.showSelect(
			fmt.Sprintf("Select model (%s, %d matches):", provider, len(filtered)),
			modelOptionsFromOpenRouter(filtered),
			func(a *App, modelValue string) {
				a.switchModel(provider, modelValue)
			},
		)
		return
	}

	a.showSelect(
		fmt.Sprintf("Select model (%s, %d total):", provider, len(models)),
		modelOptionsFromOpenRouter(models),
		func(a *App, modelValue string) {
			a.switchModel(provider, modelValue)
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
