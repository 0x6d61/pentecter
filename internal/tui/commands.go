package tui

import (
	"fmt"
	"strings"

	"github.com/0x6d61/pentecter/internal/brain"
)

// handleCommand processes slash commands. Returns true if the command was handled.
func (a *App) handleCommand(fullText string) bool {
	switch {
	case strings.HasPrefix(fullText, "/approve"):
		a.handleApproveCommand(fullText)
		return true
	case strings.HasPrefix(fullText, "/model"):
		a.handleModelCommand(fullText)
		return true
	case fullText == "/targets":
		a.handleTargetsCommand()
		return true
	case fullText == "/recontree":
		a.handleReconTreeCommand()
		return true
	case fullText == "/skip-recon":
		a.handleSkipReconCommand()
		return true
	case fullText == "/fold":
		a.toggleFold()
		return true
	case fullText == "/status":
		a.printStatusLine()
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
func (a *App) handleModelCommand(_ string) {
	detected := brain.DetectAvailableProviders()
	if len(detected) == 0 {
		a.logSystem("No providers detected. Set ANTHROPIC_API_KEY, OPENAI_API_KEY, or OLLAMA_BASE_URL.")
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
			var idx int
			if _, err := fmt.Sscanf(value, "%d", &idx); err != nil {
				return
			}
			if idx >= 0 && idx < len(a.targets) {
				a.mu.Lock()
				a.selected = idx
				a.mu.Unlock()
				a.clearAndReprint()
				a.logSystem(fmt.Sprintf("Switched to target: %s", a.targets[idx].Host))
			}
		},
	)
}

// handleReconTreeCommand displays the recon tree for the active target.
func (a *App) handleReconTreeCommand() {
	if a.selected < 0 || a.selected >= len(a.targets) {
		a.logSystem("No target selected.")
		return
	}
	target := a.targets[a.selected]
	rt := target.GetReconTree()
	if rt == nil {
		a.logSystem("No recon tree available for this target.")
		return
	}
	output := rt.RenderTree()
	a.printReconTree(target.Host, output)
}

// handleSkipReconCommand unlocks the RECON phase for the active target.
func (a *App) handleSkipReconCommand() {
	if a.selected < 0 || a.selected >= len(a.targets) {
		a.logSystem("No target selected.")
		return
	}
	target := a.targets[a.selected]
	rt := target.GetReconTree()
	if rt == nil {
		a.logSystem("No recon tree available for this target.")
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
